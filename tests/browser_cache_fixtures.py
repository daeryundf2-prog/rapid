"""Synthetic Chromium cache and WebCacheV01 fixtures, generated in code (plan r2-communication Q-R2-4/5).

Layouts follow Chromium net/disk_cache (simple_entry_format.h, blockfile/disk_format.h, addr.h),
net/http/http_response_info.cc (pickle) and content/browser/cache_storage/cache_storage.proto;
the ESE image follows the minimal catalog layout of ``tests/windows_artifact_fixtures.py``.
No real browsing data: every URL, header and body below is invented.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import struct
from pathlib import Path

SIMPLE_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_FINAL_MAGIC = 0xF4FA6F45970D41D8
INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
ADDR_INITIALIZED = 0x80000000
WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
BODY_MARKER = b"BODY-CONTENT-MUST-NOT-BE-STORED"


def webkit_micros(moment: dt.datetime) -> int:
    return (moment - WEBKIT_EPOCH) // dt.timedelta(microseconds=1)


def filetime(moment: dt.datetime) -> int:
    return webkit_micros(moment) * 10


def raw_headers(status: int, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"HTTP/1.1 {status} OK", *(f"{name}:{value}" for name, value in headers)]
    return ("\x00".join(lines) + "\x00\x00").encode("latin-1")


def response_info_pickle(raw: bytes, request_time: dt.datetime, response_time: dt.datetime, *, extra_flags: bool = True) -> bytes:
    """``HttpResponseInfo::Persist`` shape: flags [+ extra flags], times, pickled raw-header string."""
    flags = 3 | (1 << 31 if extra_flags else 0)
    payload = struct.pack("<I", flags)
    if extra_flags:
        payload += struct.pack("<I", 6)
    payload += struct.pack("<qq", webkit_micros(request_time), webkit_micros(response_time))
    if extra_flags:
        payload += struct.pack("<q", webkit_micros(response_time))
    payload += struct.pack("<I", len(raw)) + raw
    payload += b"\x00" * (-len(payload) % 4)
    return struct.pack("<I", len(payload)) + payload


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_bytes(field: int, value: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def _pb_int(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def cache_storage_metadata(method: str, status: int, headers: list[tuple[str, str]], response_time: dt.datetime, url: str) -> bytes:
    request = _pb_bytes(1, method.encode())
    response = _pb_int(1, status) + _pb_bytes(2, b"OK") + _pb_int(3, 1)
    for name, value in headers:
        response += _pb_bytes(4, _pb_bytes(1, name.encode()) + _pb_bytes(2, value.encode()))
    response += _pb_int(6, webkit_micros(response_time)) + _pb_bytes(8, url.encode())
    return _pb_bytes(1, request) + _pb_bytes(2, response) + _pb_int(3, webkit_micros(response_time))


def simple_entry(key: str, stream0: bytes, body: bytes, *, key_sha256: bool = True) -> bytes:
    key_bytes = key.encode()
    header = struct.pack("<QIII", SIMPLE_INITIAL_MAGIC, 5, len(key_bytes), 0x1234ABCD) + b"\x00" * 4
    eof1 = struct.pack("<QIIi", SIMPLE_FINAL_MAGIC, 1, 0, len(body)) + b"\x00" * 4
    flags0 = 1 | (2 if key_sha256 else 0)
    eof0 = struct.pack("<QIIi", SIMPLE_FINAL_MAGIC, flags0, 0, len(stream0)) + b"\x00" * 4
    tail = hashlib.sha256(key_bytes).digest() if key_sha256 else b""
    return header + key_bytes + body + eof1 + stream0 + tail + eof0


def entry_body(index: int, size: int = 0) -> bytes:
    base = b"<html><body>" + BODY_MARKER + f"-{index}".encode() + b"</body></html>"
    if size > len(base):
        base += b"x" * (size - len(base))
    return base


SAMPLE_URLS = [
    "https://www.example.com/index.html",
    "https://cdn.example.net/app.js",
    "https://images.example.org/logo.png",
    "https://mail.naver.com/json/write/upload/attach",
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
    "https://wetransfer.com/api/v4/transfers/link",
    "https://files.example.com/download?filename=report.pdf",
    "https://news.example.co.kr/article/1",
    "https://api.example.com/v1/items",
    "https://static.example.com/fonts/a.woff2",
]


def write_simple_cache(directory: Path, *, urls: list[str] | None = None, start: dt.datetime | None = None) -> list[dict[str, object]]:
    """10 Simple Cache entries (HTTP cache keys, pickled response info); returns the expectations."""
    directory.mkdir(parents=True, exist_ok=True)
    moment = start or dt.datetime(2024, 5, 1, 9, 0, tzinfo=dt.timezone.utc)
    expected = []
    for index, url in enumerate(urls or SAMPLE_URLS):
        upload = 7 if "upload" in url else 0
        key = f"1/{upload}/_dk_https://example.com https://example.com {url}"
        headers = [("content-type", "text/html; charset=utf-8"), ("content-length", str(100 + index)), ("server", "fixture")]
        if index == 2:
            headers.append(("content-encoding", "gzip"))
        if index == 6:
            headers.append(("content-disposition", 'attachment; filename="report.pdf"'))
        body = entry_body(index)
        response_time = moment + dt.timedelta(minutes=index)
        stream0 = response_info_pickle(raw_headers(200 + (index == 9) * 104, headers), response_time - dt.timedelta(seconds=1), response_time, extra_flags=index % 2 == 0)
        name = f"{index:016x}_0"
        (directory / name).write_bytes(simple_entry(key, stream0, body, key_sha256=index % 3 == 0))
        expected.append(
            {
                "name": name,
                "url": url,
                "method": "POST" if upload else "GET",
                "status": 304 if index == 9 else 200,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_size": len(body),
                "response_time": response_time.isoformat(),
            }
        )
    (directory / "index").write_bytes(b"\x00" * 24)
    return expected


def write_cache_storage(directory: Path) -> dict[str, object]:
    directory.mkdir(parents=True, exist_ok=True)
    url = "https://app.example.com/sw/data.json"
    moment = dt.datetime(2024, 5, 2, 8, 0, tzinfo=dt.timezone.utc)
    body = b'{"fixture": true}'
    metadata = cache_storage_metadata("GET", 200, [("Content-Type", "application/json")], moment, url)
    (directory / "00000000000000aa_0").write_bytes(simple_entry(url, metadata, body))
    return {"url": url, "response_time": moment.isoformat(), "body_sha256": hashlib.sha256(body).hexdigest()}


# --- blockfile -----------------------------------------------------------------------------


class _BlockFile:
    def __init__(self, selector: int, entry_size: int) -> None:
        self.selector = selector
        self.entry_size = entry_size
        self.blocks = bytearray()
        self.count = 0

    def add(self, data: bytes, file_type: int) -> int:
        blocks = max(1, -(-len(data) // self.entry_size))
        assert blocks <= 4
        start = self.count
        self.blocks += data.ljust(blocks * self.entry_size, b"\x00")
        self.count += blocks
        return ADDR_INITIALIZED | (file_type << 28) | ((blocks - 1) << 24) | (self.selector << 16) | start

    def image(self) -> bytes:
        header = bytearray(8192)
        struct.pack_into("<IIhhiii", header, 0, BLOCK_MAGIC, 0x20000, self.selector, 0, self.entry_size, self.count, 0x2400)
        return bytes(header) + bytes(self.blocks)


def entry_store(*, key: str, next_addr: int, rankings: int, created: dt.datetime, sizes: list[int], addrs: list[int], entry_hash: int) -> bytes:
    key_bytes = key.encode()
    data = bytearray(256)
    struct.pack_into("<IIIiiiQiI", data, 0, entry_hash, next_addr, rankings, 0, 0, 0, webkit_micros(created), len(key_bytes), 0)
    struct.pack_into("<4i", data, 40, *sizes)
    struct.pack_into("<4I", data, 56, *addrs)
    data[96 : 96 + len(key_bytes)] = key_bytes
    return bytes(data)


def write_blockfile_cache(directory: Path, *, urls: list[str] | None = None, missing_data3_index: int | None = 8) -> list[dict[str, object]]:
    """10 blockfile entries: index + data_0 (rankings) + data_1 (entries, small bodies) + data_2 (headers) + one ``f_`` body.

    Entries 0 and 1 share an index bucket (hash chain). ``missing_data3_index`` points that
    entry's headers at an absent ``data_3`` (subset-style acquisition gap).
    """
    directory.mkdir(parents=True, exist_ok=True)
    data0 = _BlockFile(0, 36)
    data1 = _BlockFile(1, 256)
    data2 = _BlockFile(2, 1024)
    table_len = 256
    table = [0] * table_len
    moment = dt.datetime(2024, 6, 1, 12, 0, tzinfo=dt.timezone.utc)
    expected: list[dict[str, object]] = []
    entries: list[tuple[int, bytes, int]] = []  # (bucket, entry bytes placeholder, addr)
    chain_head: dict[int, int] = {}
    for index, url in enumerate(urls or SAMPLE_URLS):
        upload = 9 if "upload" in url else 0
        key = f"1/{upload}/_dk_https://example.com https://example.com {url}"
        response_time = moment + dt.timedelta(minutes=index)
        headers = [("content-type", "image/png" if index == 2 else "text/html"), ("content-length", str(200 + index))]
        if index == 6:
            headers.append(("content-disposition", "attachment; filename=report.pdf"))
        meta = response_info_pickle(raw_headers(200, headers), response_time - dt.timedelta(seconds=2), response_time)
        body = (b"\x89PNG\r\n\x1a\n" + BODY_MARKER) if index == 2 else entry_body(index, 20_000 if index == 3 else 0)
        if index == missing_data3_index:
            meta_addr = ADDR_INITIALIZED | (4 << 28) | (3 << 16) | 5  # data_3, block 5: file absent
        else:
            meta_addr = data2.add(meta, 3)
        if len(body) > 256:
            file_number = 0x10 + index
            (directory / f"f_{file_number:06x}").write_bytes(body)
            body_addr = ADDR_INITIALIZED | file_number
        else:
            body_addr = data1.add(body, 2)
        rankings = data0.add(struct.pack("<QQIIIiI", webkit_micros(response_time + dt.timedelta(hours=1)), webkit_micros(response_time), 0, 0, 0, 0, 0), 1)
        bucket = 0 if index in (0, 1) else index
        entry_hash = (index << 8) | bucket
        entry = entry_store(
            key=key,
            next_addr=chain_head.get(bucket, 0),
            rankings=rankings,
            created=response_time - dt.timedelta(seconds=3),
            sizes=[len(meta), len(body), 0, 0],
            addrs=[meta_addr, body_addr, 0, 0],
            entry_hash=entry_hash,
        )
        addr = data1.add(entry, 2)
        chain_head[bucket] = addr
        table[bucket] = addr
        entries.append((bucket, entry, addr))
        expected.append(
            {
                "url": url,
                "method": "POST" if upload else "GET",
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_size": len(body),
                "response_time": response_time.isoformat(),
                "headers_missing": index == missing_data3_index,
                "external_body": len(body) > 256,
            }
        )
    index_header = bytearray(368)
    struct.pack_into("<IIiiiiIiii", index_header, 0, INDEX_MAGIC, 0x30000, len(expected), 0, 0x20, 1, 0, table_len, 0, 0)
    struct.pack_into("<Q", index_header, 40, webkit_micros(moment))
    (directory / "index").write_bytes(bytes(index_header) + struct.pack(f"<{table_len}I", *table))
    (directory / "data_0").write_bytes(data0.image())
    (directory / "data_1").write_bytes(data1.image())
    (directory / "data_2").write_bytes(data2.image())
    return expected


# --- WebCacheV01 (ESE) ----------------------------------------------------------------------

PAGE_SIZE = 8192
CATALOG_FIXED_SIZES = [4, 2, 4, 4, 4, 4, 4, 1, 2, 4, 2, 4]
# Container_N columns: (id, name, coltyp, size, codepage)
CONTAINER_COLUMNS = [
    (1, "EntryId", 15, 8, 0),
    (2, "ContainerId", 15, 8, 0),
    (3, "FileSize", 15, 8, 0),
    (4, "SecureDirectory", 14, 4, 0),
    (5, "AccessCount", 14, 4, 0),
    (6, "CreationTime", 15, 8, 0),
    (7, "ExpiryTime", 15, 8, 0),
    (8, "ModifiedTime", 15, 8, 0),
    (9, "AccessedTime", 15, 8, 0),
    (128, "Url", 10, 0, 1252),
    (129, "Filename", 10, 0, 1200),
    (130, "ResponseHeaders", 9, 0, 0),
]
CONTAINERS_COLUMNS = [
    (1, "ContainerId", 15, 8, 0),
    (128, "Name", 10, 0, 1200),
    (129, "Directory", 10, 0, 1200),
    (130, "SecureDirectories", 10, 0, 1200),
]


def _catalog_fixed(fields: dict[int, int]) -> bytes:
    region = bytearray(sum(CATALOG_FIXED_SIZES))
    offsets = {}
    running = 0
    for index, size in enumerate(CATALOG_FIXED_SIZES):
        offsets[index + 1] = running
        running += size
    for identifier, value in fields.items():
        size = CATALOG_FIXED_SIZES[identifier - 1]
        region[offsets[identifier] : offsets[identifier] + size] = int(value).to_bytes(size, "little", signed=False)
    return bytes(region)


def _record(last_fixed_id: int, fixed_region: bytes, variable_values: list[bytes]) -> bytes:
    bitmap = bytes((last_fixed_id + 7) // 8)
    variable_offset_start = 4 + len(fixed_region) + len(bitmap)
    offsets = bytearray()
    data = bytearray()
    for value in variable_values:
        data += value
        offsets += len(data).to_bytes(2, "little")
    header = bytes([last_fixed_id, 127 + len(variable_values)]) + variable_offset_start.to_bytes(2, "little")
    return header + fixed_region + bitmap + bytes(offsets) + bytes(data)


def _page(flags: int, nodes: list[bytes]) -> bytes:
    buf = bytearray(PAGE_SIZE)
    data = bytearray()
    tags = []
    for node in nodes:
        tags.append((len(node), len(data)))
        data += node
    assert 40 + len(data) + 4 * (len(nodes) + 2) < PAGE_SIZE, "fixture page overflow"
    buf[40 : 40 + len(data)] = data
    buf[32:34] = len(data).to_bytes(2, "little")
    buf[34:36] = ((1 << 12) | (len(nodes) + 1)).to_bytes(2, "little")
    buf[36:40] = flags.to_bytes(4, "little")
    for index, (size, offset) in enumerate(tags):
        position = PAGE_SIZE - 4 * (index + 2)
        buf[position : position + 2] = size.to_bytes(2, "little")
        buf[position + 2 : position + 4] = offset.to_bytes(2, "little")
    return bytes(buf)


def _encode(value: object, coltyp: int, size: int, codepage: int) -> bytes:
    if coltyp in (10, 12):
        return str(value).encode("utf-16-le" if codepage == 1200 else "cp1252")
    if coltyp in (9, 11):
        return bytes(value)  # type: ignore[arg-type]
    return int(value).to_bytes(size, "little", signed=coltyp == 15)  # type: ignore[call-overload]


def _table_row(columns: list[tuple[int, str, int, int, int]], values: dict[str, object]) -> bytes:
    fixed = [column for column in columns if column[0] <= 127]
    variable = [column for column in columns if column[0] > 127]
    fixed_region = b"".join(_encode(values.get(name, 0), coltyp, size, codepage) for _id, name, coltyp, size, codepage in fixed)
    variable_values = [_encode(values.get(name, b"" if coltyp == 9 else ""), coltyp, size, codepage) for _id, name, coltyp, size, codepage in variable]
    return (0).to_bytes(2, "little") + _record(len(fixed), fixed_region, variable_values)


def webcache_database(containers: list[dict[str, object]], rows_by_container: dict[int, list[dict[str, object]]]) -> bytes:
    """ESE image: catalog (logical page 4), ``Containers`` (page 5), one ``Container_N`` table per page after it."""
    catalog_nodes = []
    table_pages = []
    tables: list[tuple[str, list[tuple[int, str, int, int, int]], list[dict[str, object]]]] = [("Containers", CONTAINERS_COLUMNS, containers)]
    for container in containers:
        container_id = int(container["ContainerId"])  # type: ignore[call-overload]
        tables.append((f"Container_{container_id}", CONTAINER_COLUMNS, rows_by_container.get(container_id, [])))
    for table_index, (name, columns, rows) in enumerate(tables):
        root_page = 5 + table_index
        objid = 2 + table_index
        catalog_nodes.append((0).to_bytes(2, "little") + _record(12, _catalog_fixed({1: objid, 2: 1, 3: objid, 4: root_page}), [name.encode("cp1252")]))
        for identifier, column_name, coltyp, size, codepage in columns:
            fields = {1: objid, 2: 2, 3: identifier, 4: coltyp, 5: size, 7: codepage}
            catalog_nodes.append((0).to_bytes(2, "little") + _record(12, _catalog_fixed(fields), [column_name.encode("cp1252")]))
        table_pages.append(_page(0x1 | 0x2, [_table_row(columns, row) for row in rows]))
    header = bytearray(PAGE_SIZE)
    header[4:8] = (0x89ABCDEF).to_bytes(4, "little")
    header[52:56] = (2).to_bytes(4, "little")
    header[232:236] = (0x620).to_bytes(4, "little")
    header[0xEC:0xF0] = PAGE_SIZE.to_bytes(4, "little")
    blocks = [bytes(header), bytes(PAGE_SIZE), bytes(PAGE_SIZE), bytes(PAGE_SIZE), bytes(PAGE_SIZE), _page(0x1 | 0x2, catalog_nodes), *table_pages]
    return b"".join(blocks)


def utf16z(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def sample_webcache() -> tuple[bytes, dict[str, object]]:
    """History (3 rows), Content (2), Cookies (2), iedownload (1), DOMStore (1, summary only)."""
    moment = dt.datetime(2024, 7, 1, 10, 0, tzinfo=dt.timezone.utc)

    def at(minutes: int) -> int:
        return filetime(moment + dt.timedelta(minutes=minutes))

    containers = [
        {"ContainerId": 1, "Name": "History", "Directory": r"C:\Users\alice\AppData\Local\Microsoft\Windows\History\History.IE5\\", "SecureDirectories": ""},
        {"ContainerId": 2, "Name": "Content", "Directory": r"C:\Users\alice\AppData\Local\Microsoft\Windows\INetCache\IE\\", "SecureDirectories": "ABCD1234WXYZ5678"},
        {"ContainerId": 3, "Name": "Cookies", "Directory": "", "SecureDirectories": ""},
        {"ContainerId": 4, "Name": "iedownload", "Directory": "", "SecureDirectories": ""},
        {"ContainerId": 5, "Name": "DOMStore", "Directory": "", "SecureDirectories": ""},
    ]
    rows = {
        1: [
            {"EntryId": 11, "AccessCount": 3, "CreationTime": at(0), "AccessedTime": at(5), "ModifiedTime": at(5), "Url": "Visited: alice@https://intranet.example.com/home"},
            {"EntryId": 12, "AccessCount": 1, "CreationTime": at(10), "AccessedTime": at(12), "Url": "Visited: alice@https://mail.naver.com/write/upload/attach"},
            {"EntryId": 13, "AccessCount": 2, "CreationTime": at(20), "AccessedTime": at(21), "Url": "Visited: alice@file:///C:/Users/alice/Documents/plan.docx"},
        ],
        2: [
            {
                "EntryId": 21,
                "FileSize": 34,
                "SecureDirectory": 1,
                "AccessCount": 1,
                "CreationTime": at(30),
                "AccessedTime": at(31),
                "ModifiedTime": at(29),
                "Url": "https://www.example.com/logo.gif",
                "Filename": "logo[1].gif",
                "ResponseHeaders": b"HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: 34\r\n\r\n",
            },
            {"EntryId": 22, "FileSize": 10, "SecureDirectory": 0, "CreationTime": at(40), "AccessedTime": at(41), "Url": "https://www.example.com/missing.js", "Filename": "missing[1].js"},
        ],
        3: [
            {"EntryId": 31, "CreationTime": at(50), "AccessedTime": at(51), "ExpiryTime": at(60 * 24 * 30), "Url": "Cookie:alice@example.com/", "Filename": "ABCDEF.cookie"},
            {"EntryId": 32, "CreationTime": at(52), "AccessedTime": at(53), "Url": "Cookie:alice@shop.example.org/cart"},
        ],
        4: [
            {
                "EntryId": 41,
                "FileSize": 1048576,
                "CreationTime": at(70),
                "AccessedTime": at(71),
                "Url": "iedownload:https://files.example.com/setup.exe",
                "ResponseHeaders": b"\x00" * 16 + utf16z("https://files.example.com/setup.exe") + utf16z(r"C:\Users\alice\Downloads\setup.exe"),
            }
        ],
        5: [{"EntryId": 51, "CreationTime": at(80), "Url": "DOMStore:alice@example.com/"}],
    }
    expected = {"history": 3, "content": 2, "cookies": 2, "downloads": 1, "content_body": b"GIF89a" + b"\x00" * 28}
    return webcache_database(containers, rows), expected
