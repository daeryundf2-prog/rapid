from __future__ import annotations

import hashlib
import struct

from rapidtriage.core.kakaotalk_algorithms import (
    V2_PAGE_HEADER_SIZE,
    V2_PAGE_PAYLOAD_SIZE,
    V2_PAGE_RESERVED_SIZE,
    V2_PAGE_SIZE,
)

USABLE_SIZE = V2_PAGE_SIZE - V2_PAGE_RESERVED_SIZE


def sqlite_varint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    groups: list[int] = []
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    return bytes([group | 0x80 for group in groups[:-1]] + [groups[-1]])


def sqlite_record(values: list[object]) -> bytes:
    types: list[int] = []
    body = bytearray()
    for value in values:
        if value is None:
            types.append(0)
        elif isinstance(value, int):
            types.append(1)
            body += struct.pack(">b", value)
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
            types.append(len(encoded) * 2 + 13)
            body += encoded
        else:
            raise AssertionError(f"unsupported record value {value!r}")
    header = b"".join(sqlite_varint(serial_type) for serial_type in types)
    return sqlite_varint(len(header) + 1) + header + bytes(body)


def table_leaf_page(rows: list[tuple[int, list[object]]], *, header_offset: int = 0) -> bytearray:
    page = bytearray(V2_PAGE_SIZE)
    content_start = USABLE_SIZE
    pointers: list[int] = []
    for rowid, values in rows:
        payload = sqlite_record(values)
        cell = sqlite_varint(len(payload)) + sqlite_varint(rowid) + payload
        content_start -= len(cell)
        page[content_start : content_start + len(cell)] = cell
        pointers.append(content_start)
    page[header_offset : header_offset + 8] = struct.pack(">BHHHB", 0x0D, 0, len(rows), content_start, 0)
    for index, pointer in enumerate(pointers):
        start = header_offset + 8 + index * 2
        page[start : start + 2] = struct.pack(">H", pointer)
    return page


def build_reserved_sqlite(messages: list[str]) -> bytes:
    page_count = 3
    first = table_leaf_page(
        [
            (1, ["table", "chatLogs", "chatLogs", 2, "CREATE TABLE chatLogs(logId INTEGER PRIMARY KEY, message TEXT)"]),
            (2, ["table", "meta", "meta", 3, "CREATE TABLE meta(k TEXT, v TEXT)"]),
        ],
        header_offset=100,
    )
    header = bytearray(100)
    header[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">HBBBBBB", header, 16, V2_PAGE_SIZE, 1, 1, V2_PAGE_RESERVED_SIZE, 64, 32, 32)
    struct.pack_into(">II", header, 24, 1, page_count)
    struct.pack_into(">II", header, 40, 1, 4)
    struct.pack_into(">I", header, 56, 1)
    struct.pack_into(">II", header, 92, 1, 3045000)
    first[0:100] = header
    chat = table_leaf_page([(index + 1, [None, message]) for index, message in enumerate(messages)])
    meta = table_leaf_page([(1, ["fixture", "synthetic"])])
    return bytes(first + chat + meta)


def encrypt_v2_pages(plaintext: bytes, *, dek: bytes) -> bytes:
    from Crypto.Cipher import AES

    output = bytearray()
    for index, offset in enumerate(range(0, len(plaintext), V2_PAGE_SIZE)):
        page = plaintext[offset : offset + V2_PAGE_SIZE]
        iv = hashlib.sha256(b"synthetic-v2-iv-%d" % index).digest()[:16]
        cipher = AES.new(dek, AES.MODE_CBC, iv)
        if index == 0:
            body = page[:V2_PAGE_HEADER_SIZE] + cipher.encrypt(page[V2_PAGE_HEADER_SIZE:V2_PAGE_PAYLOAD_SIZE])
        else:
            body = cipher.encrypt(page[:V2_PAGE_PAYLOAD_SIZE])
        output += body + iv + b"\xee" * (V2_PAGE_SIZE - V2_PAGE_PAYLOAD_SIZE - len(iv))
    return bytes(output)
