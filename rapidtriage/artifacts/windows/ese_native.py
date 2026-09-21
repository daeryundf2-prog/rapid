"""Bounded native ESE (Extensible Storage Engine) database decoding.

Implements the minimal ESE pipeline needed to decode table rows without
a full JET engine:

- DBFILEHDR page-size detection (signature already probed by ese.py)
- PGHDR/PGHDR2 page headers and the tag array at the end of each page
- B-tree branch/leaf node parsing (key prefix + suffix compression)
- MSysObjects catalog bootstrap with the fixed catalog column schema
- RECHDR record decode: fixed columns with null bitmap, variable
  columns with the offset array, tagged columns via the TAGFLD array

Deliberately not implemented (emitted as explicit limitations):

- ESE transaction-log replay (dirty databases miss tail writes)
- Long-value page resolution (Separated columns emit LV markers)
- XPRESS/7-bit column compression (Compressed columns emit raw bytes)
- Multi-value tagged columns (emitted as raw bytes with a flag)
- Page checksum verification

The format layout follows the public Extensible-Storage-Engine sources
and is cross-checked against dissect.esedb in
scripts/srum-reference-diff.py.
"""

from __future__ import annotations

import datetime
import struct
import uuid
from collections.abc import Iterable
from typing import Any

ESE_MAGIC = 0x89ABCDEF
ESE_CATALOG_PAGE = 4  # pgnoFDPMSO
ESE_PAGE_SIZES = (2048, 4096, 8192, 16384, 32768)
ESE_MAX_PAGES = 1_000_000

# PAGE_FLAG bits
PAGE_FLAG_ROOT = 0x00000001
PAGE_FLAG_LEAF = 0x00000002
PAGE_FLAG_EMPTY = 0x00000008
PAGE_FLAG_SPACE_TREE = 0x00000020
PAGE_FLAG_LONG_VALUE = 0x00000080
PAGE_FLAG_NEW_RECORD_FORMAT = 0x00000800

# TAG_FLAG bits
TAG_FLAG_DELETED = 0x02
TAG_FLAG_COMPRESSED = 0x04

# TAGFLD header bits (large pages)
TAGFLD_LONG_VALUE = 0x01
TAGFLD_COMPRESSED = 0x02
TAGFLD_SEPARATED = 0x04
TAGFLD_MULTI_VALUES = 0x08
TAGFLD_TWO_VALUES = 0x10
TAGFLD_NULL = 0x20

# SYSOBJ types
SYSOBJ_TABLE = 1
SYSOBJ_COLUMN = 2
SYSOBJ_INDEX = 3
SYSOBJ_LONG_VALUE = 4
SYSOBJ_CALLBACK = 5

# JET_coltyp -> (name, fixed size)
COLUMN_TYPES = {
    0: ("Nil", 0),
    1: ("Bit", 1),
    2: ("UnsignedByte", 1),
    3: ("Short", 2),
    4: ("Long", 4),
    5: ("Currency", 8),
    6: ("IEEESingle", 4),
    7: ("IEEEDouble", 8),
    8: ("DateTime", 8),
    9: ("Binary", None),
    10: ("Text", None),
    11: ("LongBinary", None),
    12: ("LongText", None),
    13: ("SLV", None),
    14: ("UnsignedLong", 4),
    15: ("LongLong", 8),
    16: ("GUID", 16),
    17: ("UnsignedShort", 2),
}

CODEPAGE_MAP = {1200: "utf-16-le", 1252: "cp1252", 20127: "ascii"}

# Fixed catalog (MSysObjects) column schema: (column_id, name, coltyp[, codepage])
CATALOG_COLUMNS = (
    (1, "ObjidTable", 4),
    (2, "Type", 3),
    (3, "Id", 4),
    (4, "ColtypOrPgnoFDP", 4),
    (5, "SpaceUsage", 4),
    (6, "Flags", 4),
    (7, "PagesOrLocale", 4),
    (8, "RootFlag", 1),
    (9, "RecordOffset", 3),
    (10, "LCMapFlags", 4),
    (11, "KeyMost", 17),
    (12, "LVChunkMax", 4),
    (128, "Name", 10, 1252),
    (129, "Stats", 9),
    (130, "TemplateTable", 10, 1252),
    (131, "DefaultValue", 9),
    (132, "KeyFldIDs", 9),
    (133, "VarSegMac", 9),
    (134, "ConditionalColumns", 9),
    (135, "TupleLimits", 9),
    (136, "Version", 9),
    (137, "SortID", 9),
    (256, "CallbackData", 11),
    (257, "CallbackDependencies", 11),
    (258, "SeparateLV", 11),
    (259, "SpaceHints", 11),
    (260, "SpaceDeferredLVHints", 11),
    (261, "LocaleName", 11),
)


def read_u16(buf: bytes | memoryview, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 2], "little")


def read_u32(buf: bytes | memoryview, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "little")


def read_i32(buf: bytes | memoryview, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "little", signed=True)


class EseColumn:
    __slots__ = ("codepage", "coltyp", "default", "fixed_offset", "identifier", "name", "size")

    def __init__(self, identifier: int, name: str, coltyp: int, *, size: int = 0, codepage: int = 0):
        self.identifier = identifier
        self.name = name
        self.coltyp = coltyp
        self.size = size or (COLUMN_TYPES.get(coltyp) or (None, 0))[1] or 0
        self.codepage = codepage
        self.default = None
        self.fixed_offset = 0

    @property
    def is_fixed(self) -> bool:
        return self.identifier <= 127

    @property
    def is_variable(self) -> bool:
        return 127 < self.identifier <= 255

    @property
    def is_tagged(self) -> bool:
        return self.identifier > 255

    @property
    def is_text(self) -> bool:
        return self.coltyp in (10, 12)


class EseTag:
    __slots__ = ("data", "flags", "num", "offset", "page_num", "size")

    def __init__(self, page: EsePage, num: int):
        self.num = num
        self.page_num = page.num
        tag_offset = len(page.buf) - 4 * (num + 1)
        raw_cb = read_u16(page.buf, tag_offset)
        raw_ib = read_u16(page.buf, tag_offset + 2)
        if page.is_small_page:
            mask = 0x1FFF
            self.size = raw_cb & mask
            self.offset = raw_ib & mask
            flags = raw_ib >> 13
        else:
            mask = 0x7FFF
            self.size = raw_cb & mask
            self.offset = raw_ib & mask
            data = page.data[self.offset : self.offset + self.size]
            flags = data[1] >> 5 if len(data) >= 2 else 0
        self.flags = flags
        self.data = page.data[self.offset : self.offset + self.size]


class EseNode:
    __slots__ = ("data", "deleted", "key", "page_flags", "page_num", "record_file_offset", "tag_num")

    def __init__(self, tag: EseTag, page: EsePage):
        buf = tag.data
        offset = 0
        self.page_flags = page.flags
        self.page_num = page.num
        self.tag_num = tag.num
        # Logical page N is physical page index N+1 (pages 1-2 are the
        # header/shadow); tag.offset is relative to the post-header
        # page data region.
        self.record_file_offset = (page.num + 1) * len(page.buf) + page.data_start + tag.offset
        key_prefix = b""
        if len(buf) >= 2 and tag.flags & TAG_FLAG_COMPRESSED:
            key_prefix_size = read_u16(buf, 0) & 0x1FFF
            prefix = page.key_prefix or b""
            key_prefix = prefix[:key_prefix_size].ljust(key_prefix_size, b"\x00")
            offset += 2
        key_suffix = b""
        if len(buf) >= offset + 2:
            key_suffix_size = read_u16(buf, offset) & 0x1FFF
            offset += 2
            key_suffix = bytes(buf[offset : offset + key_suffix_size])
            offset += key_suffix_size
        self.key = key_prefix + key_suffix
        self.data = buf[offset:]
        self.deleted = bool(tag.flags & TAG_FLAG_DELETED)

    @property
    def child_page(self) -> int:
        return int.from_bytes(self.data[:4], "little") if len(self.data) >= 4 else 0


class EsePage:
    __slots__ = (
        "buf",
        "data",
        "data_start",
        "flags",
        "is_small_page",
        "key_prefix",
        "next_page",
        "node_count",
        "num",
        "tag_count",
    )

    def __init__(self, num: int, buf: bytes, *, is_small_page: bool):
        self.num = num
        self.buf = buf
        self.is_small_page = is_small_page
        self.data_start = 40
        self.next_page = read_u32(buf, 20)
        if not is_small_page:
            self.data_start += 40
        ib_mic_free = read_u16(buf, 32)
        itag_state = read_u16(buf, 34)
        self.flags = read_u32(buf, 36)
        tag_reserved = (itag_state >> 12) or 1
        self.tag_count = itag_state & 0x0FFF
        self.node_count = self.tag_count - tag_reserved
        self.data = buf[self.data_start : self.data_start + ib_mic_free]
        self.key_prefix = b"" if self.is_root else self._tag_data(0)

    def _tag_data(self, num: int) -> bytes:
        tag_offset = len(self.buf) - 4 * (num + 1)
        raw_cb = read_u16(self.buf, tag_offset)
        raw_ib = read_u16(self.buf, tag_offset + 2)
        mask = 0x1FFF if self.is_small_page else 0x7FFF
        size = raw_cb & mask
        offset = raw_ib & mask
        return bytes(self.data[offset : offset + size])

    @property
    def is_root(self) -> bool:
        return bool(self.flags & PAGE_FLAG_ROOT)

    @property
    def is_leaf(self) -> bool:
        return bool(self.flags & PAGE_FLAG_LEAF)

    def tag(self, num: int) -> EseTag | None:
        if num < 0 or num >= self.tag_count:
            return None
        try:
            tag = EseTag(self, num)
        except (IndexError, struct.error):
            return None
        if tag.size == 0 and num != 0:
            return None
        return tag

    def nodes(self) -> Iterable[EseNode]:
        for index in range(self.node_count):
            tag = self.tag(index + 1)
            if tag is None:
                continue
            try:
                yield EseNode(tag, self)
            except (IndexError, struct.error):
                continue


class EseTagField:
    __slots__ = ("flags", "has_extended_info", "identifier", "is_null", "offset")

    def __init__(self, value: int, *, is_small_page: bool, data: bytes | memoryview, tagged_start: int):
        self.identifier = value & 0xFFFF
        raw_offset = (value >> 16) & 0xFFFF
        if is_small_page:
            self.offset = raw_offset & 0x1FFF
            self.has_extended_info = bool(raw_offset & 0x4000)
            self.is_null = bool(raw_offset & 0x2000)
            self.flags = 0
        else:
            self.offset = raw_offset & 0x7FFF
            self.has_extended_info = True
            flag_index = tagged_start + self.offset
            self.flags = data[flag_index] if flag_index < len(data) else 0
            self.is_null = bool(self.flags & TAGFLD_NULL)


class EseRecordData:
    """Decode the fixed/variable/tagged regions of a leaf node payload."""

    __slots__ = (
        "data",
        "fixed_null_bitmap",
        "header_ok",
        "is_small_page",
        "last_fixed_id",
        "last_variable_id",
        "new_record_format",
        "tagged_data_start",
        "tagged_fields",
        "variable_data_start",
        "variable_offset_start",
        "variable_offsets",
    )

    def __init__(self, data: bytes | memoryview, *, new_record_format: bool, is_small_page: bool):
        self.data = data
        self.new_record_format = new_record_format
        self.is_small_page = is_small_page
        self.header_ok = len(data) >= 4
        self.last_fixed_id = 0
        self.last_variable_id = 0
        self.variable_offset_start = 0
        self.variable_data_start = 0
        self.variable_offsets: list[int] = []
        self.fixed_null_bitmap = b""
        self.tagged_data_start = 0
        self.tagged_fields: list[EseTagField] = []
        if not self.header_ok:
            return
        self.last_fixed_id = data[0]
        self.last_variable_id = data[1]
        self.variable_offset_start = read_u16(data, 2)
        bitmap_size = (self.last_fixed_id + 7) // 8
        bitmap_start = self.variable_offset_start - bitmap_size
        if 0 <= bitmap_start <= len(data):
            self.fixed_null_bitmap = bytes(data[bitmap_start : self.variable_offset_start])
        num_variable = self.last_variable_id - 127
        self.variable_data_start = self.variable_offset_start + num_variable * 2
        if 0 < num_variable <= 128 and self.variable_offset_start + num_variable * 2 <= len(data):
            self.variable_offsets = list(
                struct.unpack(
                    f"<{num_variable}H",
                    data[self.variable_offset_start : self.variable_data_start],
                )
            )
        self.tagged_data_start = self.variable_data_start
        if self.variable_offsets:
            self.tagged_data_start += self.variable_offsets[-1] & 0x7FFF
        if self.new_record_format and len(self.data) >= self.tagged_data_start + 4:
            first_value = read_u32(self.data, self.tagged_data_start)
            tagged_count = ((first_value >> 16) & 0x7FFF if not is_small_page else (first_value >> 16) & 0x1FFF) // 4
            tagged_count = min(tagged_count, 512)
            for index in range(tagged_count):
                value = read_u32(self.data, self.tagged_data_start + index * 4)
                self.tagged_fields.append(
                    EseTagField(value, is_small_page=is_small_page, data=self.data, tagged_start=self.tagged_data_start)
                )

    def _fixed(self, column: EseColumn) -> bytes | None:
        if column.identifier <= self.last_fixed_id:
            bit_index = column.identifier - 1
            bitmap_offset, bitmap_shift = divmod(bit_index, 8)
            if bitmap_offset < len(self.fixed_null_bitmap) and (
                self.fixed_null_bitmap[bitmap_offset] & (1 << bitmap_shift)
            ):
                return None
            offset = 4 + column.fixed_offset
            end = offset + column.size
            if end <= len(self.data):
                return bytes(self.data[offset:end])
            return None
        return column.default

    def _variable(self, column: EseColumn) -> bytes | None:
        if column.identifier <= self.last_variable_id and self.variable_offsets:
            index = column.identifier - 128
            if index >= len(self.variable_offsets):
                return column.default
            value_start = 0 if index == 0 else self.variable_offsets[index - 1] & 0x7FFF
            value_end = self.variable_offsets[index]
            if value_end & 0x8000:
                return None
            start = self.variable_data_start + value_start
            end = self.variable_data_start + value_end
            if 0 <= start <= end <= len(self.data):
                return bytes(self.data[start:end])
            return None
        return column.default

    def _tagged(self, column: EseColumn) -> tuple[EseTagField | None, bytes | None, list[str]]:
        markers: list[str] = []
        index = next(
            (i for i, item in enumerate(self.tagged_fields) if item.identifier == column.identifier),
            None,
        )
        if index is None:
            return None, column.default, markers
        field = self.tagged_fields[index]
        data_start = field.offset + (1 if field.has_extended_info else 0)
        data_end = (
            self.tagged_fields[index + 1].offset
            if index + 1 < len(self.tagged_fields)
            else len(self.data)
        )
        if field.is_null:
            return field, None, markers
        start = self.tagged_data_start + data_start
        end = min(self.tagged_data_start + data_end, len(self.data))
        if not (0 <= start <= end):
            return field, None, markers + ["tagged-bounds-invalid"]
        value = bytes(self.data[start:end])
        if field.flags & TAGFLD_SEPARATED:
            markers.append("lv-separated-value")
            return field, value, markers
        if field.flags & TAGFLD_COMPRESSED:
            markers.append("compressed-value-not-decompressed")
            return field, value, markers
        if field.flags & (TAGFLD_MULTI_VALUES | TAGFLD_TWO_VALUES):
            markers.append("multi-value-raw")
            return field, value, markers
        return field, value, markers

    def value(self, column: EseColumn) -> tuple[Any, list[str]]:
        if not self.header_ok:
            return None, ["record-header-missing"]
        markers: list[str] = []
        if column.is_fixed:
            raw = self._fixed(column)
        elif column.is_variable:
            raw = self._variable(column)
        else:
            field, raw, markers = self._tagged(column)
        if raw is None:
            return None, markers
        return parse_column_value(column, raw), markers


def parse_column_value(column: EseColumn, raw: bytes) -> Any:
    coltyp = column.coltyp
    if coltyp == 1:
        return raw[0] == 0xFF if raw else None
    if coltyp in (2,):
        return raw[0] if raw else None
    if coltyp == 3:
        return int.from_bytes(raw[:2], "little", signed=True) if len(raw) >= 2 else None
    if coltyp == 4:
        return int.from_bytes(raw[:4], "little", signed=True) if len(raw) >= 4 else None
    if coltyp in (5, 15):
        return int.from_bytes(raw[:8], "little", signed=True) if len(raw) >= 8 else None
    if coltyp == 6:
        return struct.unpack("<f", raw[:4])[0] if len(raw) >= 4 else None
    if coltyp == 7:
        return struct.unpack("<d", raw[:8])[0] if len(raw) >= 8 else None
    if coltyp == 8:
        if len(raw) < 8:
            return None
        days = struct.unpack("<d", raw[:8])[0]
        try:
            return (datetime.datetime(1899, 12, 30) + datetime.timedelta(days=days)).isoformat()
        except (OverflowError, ValueError):
            return None
    if coltyp in (9, 11, 13):
        return bytes(raw)
    if coltyp in (10, 12):
        encoding = CODEPAGE_MAP.get(column.codepage, "cp1252")
        buf = bytes(raw)
        if encoding == "utf-16-le" and len(buf) % 2:
            buf += b"\x00"
        return buf.decode(encoding, errors="backslashreplace").rstrip("\x00")
    if coltyp == 14:
        return int.from_bytes(raw[:4], "little") if len(raw) >= 4 else None
    if coltyp == 16:
        return str(uuid.UUID(bytes_le=bytes(raw[:16]))) if len(raw) >= 16 else None
    if coltyp == 17:
        return int.from_bytes(raw[:2], "little") if len(raw) >= 2 else None
    return bytes(raw)


class EseTable:
    __slots__ = ("column_id_map", "columns", "lv_root_page", "name", "root_page")

    def __init__(self, name: str, root_page: int):
        self.name = name
        self.root_page = root_page
        self.columns: list[EseColumn] = []
        self.column_id_map: dict[int, EseColumn] = {}
        self.lv_root_page = 0

    def add_column(self, column: EseColumn) -> None:
        if column.is_fixed:
            column.fixed_offset = sum(c.size for c in self.columns if c.is_fixed)
        self.columns.append(column)
        self.column_id_map[column.identifier] = column


class EseDatabase:
    """Bounded ESE reader: catalog bootstrap + leaf-page row iteration."""

    def __init__(self, blob: bytes):
        self.blob = blob
        self.page_size = 0
        self.format_major = 0
        self.format_minor = 0
        self.tables: list[EseTable] = []
        self.limitations: list[str] = []
        self.errors: list[str] = []
        self._page_cache: dict[int, EsePage] = {}
        self._parse_header()
        if self.page_size:
            self._parse_catalog()

    def _parse_header(self) -> None:
        if len(self.blob) < 240 or read_u32(self.blob, 4) != ESE_MAGIC:
            self.errors.append("invalid-ese-header")
            return
        page_size = read_u32(self.blob, 0xEC)
        self.page_size = page_size if page_size in ESE_PAGE_SIZES else 4096
        self.format_major = read_u32(self.blob, 232)
        self.format_minor = read_u32(self.blob, 644) if len(self.blob) >= 648 else 0
        dbstate = read_u32(self.blob, 52)
        if dbstate != 2:
            self.limitations.append(
                f"database dirty-state={dbstate}: transaction-log replay not performed, tail rows may be missing"
            )
        if self.format_major < 9:
            self.errors.append(f"unsupported-format-major={self.format_major}")
            self.page_size = 0

    @property
    def is_small_page(self) -> bool:
        return self.page_size <= 8192

    @property
    def page_count(self) -> int:
        # Pages 1 and 2 are the header and shadow-header pages; logical
        # page numbering starts at physical page index 2.
        return len(self.blob) // self.page_size - 2 if self.page_size else 0

    def page(self, num: int) -> EsePage | None:
        if num < 1 or num > min(self.page_count, ESE_MAX_PAGES):
            return None
        if num not in self._page_cache:
            start = (num + 1) * self.page_size
            buf = self.blob[start : start + self.page_size]
            if len(buf) != self.page_size or len(buf) < 44:
                return None
            try:
                page = EsePage(num, buf, is_small_page=self.is_small_page)
            except (IndexError, struct.error):
                return None
            self._page_cache[num] = page
        return self._page_cache[num]

    def iter_leaf_nodes(
        self,
        page: EsePage | None,
        *,
        depth: int = 0,
        visited: set[int] | None = None,
    ) -> Iterable[EseNode]:
        if page is None or depth > 8:
            return
        visited = visited if visited is not None else set()
        if page.num in visited:
            return
        visited.add(page.num)
        last_leaf_page = 0
        for node in page.nodes():
            if page.is_leaf:
                yield node
            else:
                child = self.page(node.child_page)
                yield from self.iter_leaf_nodes(child, depth=depth + 1, visited=visited)
                if child is not None and child.is_leaf:
                    last_leaf_page = child.num
        if page.is_root and last_leaf_page:
            # dissect.esedb heuristic: the last leaf's next_page may hold
            # sibling leaves outside the branch walk on dirty databases.
            leaf = self.page(last_leaf_page)
            next_page = leaf.next_page if leaf is not None else 0
            if next_page and next_page not in visited:
                yield from self.iter_leaf_nodes(self.page(next_page), depth=depth + 1, visited=visited)

    def _decode_catalog_record(self, node: EseNode, columns: list[EseColumn]) -> dict[int, Any]:
        record = EseRecordData(
            node.data,
            new_record_format=bool(node.page_flags & PAGE_FLAG_NEW_RECORD_FORMAT),
            is_small_page=self.is_small_page,
        )
        out: dict[int, Any] = {}
        for column in columns:
            value, _markers = record.value(column)
            out[column.identifier] = value
        return out

    def _parse_catalog(self) -> None:
        catalog_columns = [
            EseColumn(entry[0], entry[1], entry[2], codepage=entry[3] if len(entry) > 3 else 0)
            for entry in CATALOG_COLUMNS
        ]
        fixed_offset = 0
        for column in catalog_columns:
            if column.is_fixed:
                column.fixed_offset = fixed_offset
                fixed_offset += column.size
        root = self.page(ESE_CATALOG_PAGE)
        if root is None:
            self.errors.append("catalog-root-page-unreadable")
            return
        current: EseTable | None = None
        for node in self.iter_leaf_nodes(root):
            row = self._decode_catalog_record(node, catalog_columns)
            rtype = row.get(2)
            if rtype == SYSOBJ_TABLE:
                name = row.get(128)
                root_page = row.get(4) or 0
                current = EseTable(str(name or ""), int(root_page))
                self.tables.append(current)
            elif rtype == SYSOBJ_COLUMN and current is not None:
                column = EseColumn(
                    int(row.get(3) or 0),
                    str(row.get(128) or ""),
                    int(row.get(4) or 0),
                    size=int(row.get(5) or 0),
                    codepage=int(row.get(7) or 0),
                )
                default_raw = row.get(131)
                if isinstance(default_raw, bytes) and default_raw:
                    column.default = parse_column_value(column, default_raw)
                current.add_column(column)
            elif rtype == SYSOBJ_LONG_VALUE and current is not None:
                current.lv_root_page = int(row.get(4) or 0)
        if not self.tables:
            self.errors.append("catalog-decoded-no-tables")

    def iter_table_rows(self, table: EseTable) -> Iterable[tuple[EseNode, dict[str, Any], list[str]]]:
        root = self.page(table.root_page)
        for node in self.iter_leaf_nodes(root):
            record = EseRecordData(
                node.data,
                new_record_format=bool(node.page_flags & PAGE_FLAG_NEW_RECORD_FORMAT),
                is_small_page=self.is_small_page,
            )
            row: dict[str, Any] = {}
            markers: list[str] = []
            for column in table.columns:
                value, column_markers = record.value(column)
                if column_markers:
                    markers.extend(f"{column.name}:{m}" for m in column_markers)
                if value is not None:
                    row[column.name] = value
            yield node, row, markers


def decode_ese_database(blob: bytes, *, max_rows_per_table: int = 250_000) -> dict[str, object]:
    """Decode an ESE database blob into a structured profile + row map.

    Returns a dict with table metadata, per-table decoded rows (bounded),
    and explicit limitation markers. Rows are keyed by column name.
    """
    db = EseDatabase(blob)
    result: dict[str, object] = {
        "page_size": db.page_size,
        "page_count": db.page_count,
        "format_major": db.format_major,
        "format_minor": db.format_minor,
        "limitations": list(db.limitations),
        "errors": list(db.errors),
        "tables": [],
    }
    for table in db.tables:
        table_entry: dict[str, object] = {
            "name": table.name,
            "root_page": table.root_page,
            "columns": [
                {
                    "identifier": c.identifier,
                    "name": c.name,
                    "coltyp": c.coltyp,
                    "coltyp_name": COLUMN_TYPES.get(c.coltyp, ("Unknown", None))[0],
                    "class": "fixed" if c.is_fixed else "variable" if c.is_variable else "tagged",
                }
                for c in table.columns
            ],
            "lv_root_page": table.lv_root_page,
            "rows": [],
            "row_count": 0,
            "truncated": False,
            "marker_counts": {},
        }
        marker_counts: dict[str, int] = {}
        count = 0
        for _node, row, markers in db.iter_table_rows(table):
            count += 1
            for marker in markers:
                marker_counts[marker] = marker_counts.get(marker, 0) + 1
            if len(table_entry["rows"]) < max_rows_per_table:
                serializable = {
                    key: (value.hex() if isinstance(value, (bytes, bytearray)) else value)
                    for key, value in row.items()
                }
                table_entry["rows"].append(serializable)
        table_entry["row_count"] = count
        table_entry["truncated"] = count > max_rows_per_table
        table_entry["marker_counts"] = marker_counts
        result["tables"].append(table_entry)
    return result
