"""Chromium HTTP cache entry decoding (plan r2-communication §3.3 M3).

Three on-disk layouts are decoded into plain ``dict`` rows (``browser.py`` wraps
them as ``browser-cache-entry`` records):

- **Simple Cache** (``<16 hex>_0`` files; net/disk_cache/simple/simple_entry_format.h):
  ``SimpleFileHeader`` (initial magic, version, key length, key hash; 24 bytes), the
  key, stream 1 (the body) closed by a ``SimpleFileEOF`` (final magic, flags, CRC,
  stream size; 24 bytes), stream 0 (the response metadata), an optional key SHA-256
  and the stream-0 EOF at the end of the file.
- **Blockfile** (``index`` + ``data_0..3`` + ``f_*``; net/disk_cache/blockfile/disk_format.h):
  the ``index`` hash table (368-byte ``IndexHeader`` then ``table_len`` cache
  addresses) points at 256-byte ``EntryStore`` blocks in ``data_1``; an entry's stream 0
  (response metadata) and stream 1 (body) live in a block file (``data_N``) or in an
  external ``f_XXXXXX`` file; its ``rankings_node`` (``data_0``) holds last-used/modified.
- **CacheStorage** (Service Worker ``CacheStorage/<origin>/<cache>/``): Simple Cache files
  whose stream 0 is a ``CacheMetadata`` protobuf (content/browser/cache_storage/cache_storage.proto).

Stream 0 of the HTTP cache is a pickled ``HttpResponseInfo`` (uint32 payload size, int32
flags [+ int32 extra flags], int64 request/response[/original response] times in
microseconds since 1601-01-01, then the raw headers as a pickled string with ``\\0``
separators).

Bodies are **never stored**: only their size, SHA-256 (full body up to
``MAX_BODY_READ_BYTES``; above that a prefix digest marked as such), a SHA-256 of the
first 256 bytes and a magic-byte type label. Caps: ``MAX_CACHE_ENTRIES`` entries per
provider run (shared :class:`CacheBudget`), bounded key / metadata / chain reads. A
corrupt entry is isolated (an error item, the directory keeps decoding).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import struct
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote, urlsplit

CACHE_PARSER = "chromium-cache-entry"
CACHE_PARSER_VERSION = "chromium-cache-v1"
MAX_CACHE_ENTRIES = 200_000
MAX_BODY_READ_BYTES = 4 * 1024 * 1024
BODY_HEAD_BYTES = 256
MAX_STREAM0_BYTES = 512 * 1024
MAX_KEY_BYTES = 16 * 1024
MAX_CHAIN_LENGTH = 64
MAX_CACHE_KEY_CHARS = 2048
MAX_ERROR_SAMPLES = 20
MAX_SCAN_BLOCKS = 65_536

SIMPLE_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_FINAL_MAGIC = 0xF4FA6F45970D41D8
SIMPLE_HEADER_SIZE = 24
SIMPLE_EOF_SIZE = 24
SIMPLE_EOF_FLAG_HAS_KEY_SHA256 = 0x2
SIMPLE_ENTRY_NAME = re.compile(r"^[0-9a-f]{16}_0$")

INDEX_MAGIC = 0xC103CAC3
BLOCK_MAGIC = 0xC104CAC3
INDEX_HEADER_SIZE = 368
INDEX_DEFAULT_TABLE_LEN = 0x10000
INDEX_MAX_TABLE_LEN = 1 << 22
BLOCK_HEADER_SIZE = 8192
ENTRY_STORE_SIZE = 256
ENTRY_KEY_OFFSET = 96
RANKINGS_NODE_SIZE = 36
# CacheAddr (net/disk_cache/blockfile/addr.h)
ADDR_INITIALIZED = 0x80000000
FILE_TYPE_EXTERNAL = 0
FILE_TYPE_RANKINGS = 1
BLOCK_SIZES = {1: 36, 2: 256, 3: 1024, 4: 4096, 5: 8, 6: 104, 7: 48}
ENTRY_STATES = {0: "normal", 1: "evicted", 2: "doomed"}
ENTRY_FLAG_PARENT = 0x1
ENTRY_FLAG_CHILD = 0x2

# HttpResponseInfo flags (net/http/http_response_info.cc).
RESPONSE_INFO_TRUNCATED = 1 << 12
RESPONSE_INFO_HAS_EXTRA_FLAGS = 1 << 31

WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
PLAUSIBLE_MIN_MICROS = 11_644_473_600_000_000  # 1970-01-01
PLAUSIBLE_MAX_MICROS = 16_000_000_000_000_000  # ~2108

COMPRESSION_TOKENS = ("gzip", "br", "deflate", "zstd", "compress", "x-gzip")
KEPT_HEADERS = (
    "content-type",
    "content-length",
    "content-encoding",
    "content-disposition",
    "last-modified",
    "etag",
    "server",
    "date",
    "location",
    "cache-control",
    "expires",
    "age",
)
BODY_POLICY = "본문은 저장하지 않음(크기·SHA-256·앞 256바이트 서명만 기록)"
FILE_NAME_QUERY_KEYS = ("filename", "fileName", "file_name", "name", "fname", "attachName", "title")


class CacheEntryError(ValueError):
    """One cache entry could not be decoded (isolated; the directory keeps decoding)."""


class MissingCacheFile(CacheEntryError):
    def __init__(self, name: str) -> None:
        super().__init__(f"missing-file:{name}")
        self.name = name


class CacheBudget:
    """Entry cap shared by every cache directory of one provider run."""

    __slots__ = ("cap", "capped", "used")

    def __init__(self, cap: int = MAX_CACHE_ENTRIES) -> None:
        self.cap = cap
        self.used = 0
        self.capped = False

    def take(self) -> bool:
        if self.used >= self.cap:
            self.capped = True
            return False
        self.used += 1
        return True


class CacheDirectoryResult:
    __slots__ = ("cache_format", "directory", "entries", "error_count", "error_samples", "notes")

    def __init__(self, directory: Path, cache_format: str) -> None:
        self.directory = directory
        self.cache_format = cache_format
        self.entries: list[dict[str, object]] = []
        self.error_count = 0
        self.error_samples: list[dict[str, object]] = []
        self.notes: list[str] = []

    def error(self, *, source_path: Path | str, offset: int | None, reason: str) -> None:
        self.error_count += 1
        if len(self.error_samples) < MAX_ERROR_SAMPLES:
            self.error_samples.append({"source_path": str(source_path), "source_offset": offset, "reason": reason[:200]})


# --- small helpers ---------------------------------------------------------------


def webkit_time(micros: int | None) -> str | None:
    """Chromium ``base::Time`` internal value (µs since 1601-01-01 UTC) as ISO-8601, else None."""
    if micros is None or not PLAUSIBLE_MIN_MICROS <= micros <= PLAUSIBLE_MAX_MICROS:
        return None
    try:
        return (WEBKIT_EPOCH + dt.timedelta(microseconds=micros)).isoformat()
    except OverflowError:
        return None


def normalize_host(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().removeprefix("www.")


def parse_cache_key(key: str) -> dict[str, object]:
    """URL, upload id and isolation key of an HTTP cache key.

    ``HttpCache::GenerateCacheKey``: ``<credentials>/<upload id>/`` then, with split
    caching, ``_dk_<top-frame site> <frame site> <url>`` (``_dk_s_``/``_cn_`` variants);
    the URL is the last space-separated token. A non-zero upload id means the request had
    a body (POST/PUT). CacheStorage keys are the bare URL.
    """
    text = key.strip("\x00").strip()
    upload_id = 0
    rest = text
    match = re.match(r"^(\d+)/(\d+)/(.*)$", text, flags=re.DOTALL)
    if match:
        upload_id = int(match.group(2))
        rest = match.group(3)
    tokens = rest.split(" ")
    url = tokens[-1] if tokens else rest
    isolation = " ".join(tokens[:-1]).removeprefix("_dk_s_").removeprefix("_dk_").removeprefix("_cn_").strip()
    url = url.removeprefix("_dk_")
    return {
        "url": url,
        "upload_id": upload_id,
        "isolation_key": isolation,
        "method": "POST" if upload_id else "GET",
        "method_basis": "cache-key-upload-id" if upload_id else "cache-key",
    }


def parse_raw_headers(raw: str) -> dict[str, object]:
    """Status and kept headers of ``HttpResponseHeaders`` raw text (``\\0`` or CRLF separated)."""
    lines = [line for line in re.split(r"\x00|\r?\n", raw) if line]
    status_line = lines[0] if lines and lines[0].upper().startswith("HTTP/") else ""
    status: int | None = None
    version = ""
    if status_line:
        parts = status_line.split(" ", 2)
        version = parts[0]
        if len(parts) > 1 and parts[1][:3].isdigit():
            status = int(parts[1][:3])
    headers: dict[str, str] = {}
    names: list[str] = []
    for line in lines[1 if status_line else 0 :]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if not name or len(name) > 80:
            continue
        if name not in names:
            names.append(name)
        if name in KEPT_HEADERS and name not in headers:
            headers[name] = value.strip()[:500]
    return {"status_line": status_line[:200], "http_version": version, "http_status": status, "headers": headers, "header_names": names[:80]}


def content_disposition_filename(value: str) -> str:
    if not value:
        return ""
    match = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", value, flags=re.IGNORECASE)
    if match:
        return unquote(match.group(1).strip().strip('"'))[:260]
    match = re.search(r'filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)', value, flags=re.IGNORECASE)
    if match:
        return (match.group(1) or match.group(2) or "").strip()[:260]
    return ""


def header_fields(parsed: Mapping[str, object]) -> dict[str, object]:
    headers = parsed.get("headers")
    if not isinstance(headers, Mapping):
        headers = {}
    length_text = str(headers.get("content-length") or "").strip()
    encoding = str(headers.get("content-encoding") or "").strip().lower()
    disposition = str(headers.get("content-disposition") or "")
    return {
        "http_status": parsed.get("http_status"),
        "status_line": parsed.get("status_line") or "",
        "http_version": parsed.get("http_version") or "",
        "content_type": str(headers.get("content-type") or "")[:200],
        "content_length": int(length_text) if length_text.isdigit() else None,
        "content_encoding": encoding,
        "compression": next((token for token in COMPRESSION_TOKENS if token in encoding), ""),
        "content_disposition": disposition[:300],
        "file_name_candidate": content_disposition_filename(disposition),
        "server": str(headers.get("server") or "")[:200],
        "etag": str(headers.get("etag") or "")[:200],
        "last_modified_header": str(headers.get("last-modified") or "")[:100],
        "date_header": str(headers.get("date") or "")[:100],
        "location": str(headers.get("location") or "")[:1000],
        "cache_control": str(headers.get("cache-control") or "")[:200],
        "response_header_names": parsed.get("header_names") or [],
    }


def body_signature(head: bytes) -> str:
    """Magic-byte type label of the first bytes of a body (never the bytes themselves)."""
    if not head:
        return "empty"
    signatures = (
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF8", "gif"),
        (b"%PDF", "pdf"),
        (b"PK\x03\x04", "zip"),
        (b"\x1f\x8b", "gzip"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"wOFF", "woff"),
        (b"wOF2", "woff2"),
        (b"ID3", "mp3"),
        (b"\x00asm", "wasm"),
        (b"BM", "bmp"),
        (b"\xd0\xcf\x11\xe0", "ole"),
    )
    for magic, label in signatures:
        if head.startswith(magic):
            return label
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[4:8] == b"ftyp":
        return "mp4"
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "html"
    if stripped.startswith((b"<?xml", b"<svg")):
        return "xml"
    if stripped.startswith((b"{", b"[")):
        return "json-like"
    printable = sum(1 for byte in head if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 0xC0)
    return "text" if printable / len(head) > 0.9 else "binary"


def body_profile_from_reader(chunks: Iterator[bytes], size: int) -> dict[str, object]:
    """Hash a body stream (bounded by ``MAX_BODY_READ_BYTES``); the bytes are dropped."""
    digest = hashlib.sha256()
    head = b""
    read = 0
    for chunk in chunks:
        if not chunk:
            break
        if len(head) < BODY_HEAD_BYTES:
            head += chunk[: BODY_HEAD_BYTES - len(head)]
        digest.update(chunk)
        read += len(chunk)
    complete = read >= size
    if not size:
        scope = "empty"
    elif complete:
        scope = "full"
    elif read < min(size, MAX_BODY_READ_BYTES):
        scope = f"short-read-{read}-of-{size}-bytes"  # the stored stream ends before its recorded size
    else:
        scope = f"prefix-{read}-bytes"
    return {
        "body_size": size,
        "body_sha256": digest.hexdigest() if complete and size else None,
        "body_prefix_sha256": digest.hexdigest() if not complete and read else None,
        "body_hash_scope": scope,
        "body_hash_basis": "저장된 바이트(Content-Encoding 해제 전)",
        "body_head_sha256": hashlib.sha256(head).hexdigest() if head else None,
        "body_signature": body_signature(head),
        "body_stored": False,
        "body_policy": BODY_POLICY,
    }


def read_chunks(handle: BinaryIO, offset: int, size: int) -> Iterator[bytes]:
    handle.seek(offset)
    remaining = min(size, MAX_BODY_READ_BYTES)
    while remaining > 0:
        chunk = handle.read(min(remaining, 1024 * 1024))
        if not chunk:
            return
        remaining -= len(chunk)
        yield chunk


# --- stream 0 decoders -------------------------------------------------------------


def parse_response_info_pickle(blob: bytes) -> dict[str, object]:
    """``HttpResponseInfo`` pickle: times + raw headers (net/http/http_response_info.cc)."""
    if len(blob) < 12:
        raise CacheEntryError("response-info-too-short")
    payload = struct.unpack_from("<I", blob, 0)[0]
    if payload > len(blob) - 4 or payload < 8:
        raise CacheEntryError("response-info-bad-payload-size")
    flags = struct.unpack_from("<I", blob, 4)[0]
    position = 8
    if flags & RESPONSE_INFO_HAS_EXTRA_FLAGS:
        position += 4
    times: list[int] = []
    raw = ""
    for _ in range(5):
        if position + 9 <= len(blob) and blob[position + 4 : position + 9] == b"HTTP/":
            length = struct.unpack_from("<I", blob, position)[0]
            raw = blob[position + 4 : position + 4 + min(length, MAX_STREAM0_BYTES)].decode("latin-1")
            break
        if position + 8 > len(blob):
            break
        times.append(struct.unpack_from("<q", blob, position)[0])
        position += 8
    if not raw:
        start = blob.find(b"HTTP/")
        if start < 0:
            raise CacheEntryError("response-info-no-headers")
        end = blob.find(b"\x00\x00", start)
        raw = blob[start : end if end > 0 else len(blob)].decode("latin-1")
    parsed = parse_raw_headers(raw)
    result = header_fields(parsed)
    result.update(
        {
            "request_time": webkit_time(times[0]) if len(times) > 0 else None,
            "response_time": webkit_time(times[1]) if len(times) > 1 else None,
            "original_response_time": webkit_time(times[2]) if len(times) > 2 else None,
            "response_info_version": flags & 0xFF,
            "response_truncated": bool(flags & RESPONSE_INFO_TRUNCATED),
            "metadata_format": "http-response-info-pickle",
        }
    )
    return result


def _varint(blob: bytes, position: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while position < len(blob) and shift < 70:
        byte = blob[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, position
        shift += 7
    raise CacheEntryError("protobuf-truncated-varint")


def iter_protobuf(blob: bytes) -> Iterator[tuple[int, int | bytes]]:
    """(field number, value) of one protobuf message level: varints as ``int``, the rest as ``bytes``."""
    position = 0
    count = 0
    while position < len(blob):
        count += 1
        if count > 4096:
            raise CacheEntryError("protobuf-too-many-fields")
        tag, position = _varint(blob, position)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            value, position = _varint(blob, position)
            yield field, value
        elif wire in (1, 5):
            width = 8 if wire == 1 else 4
            yield field, blob[position : position + width]
            position += width
        elif wire == 2:
            length, position = _varint(blob, position)
            if position + length > len(blob):
                raise CacheEntryError("protobuf-truncated-bytes")
            yield field, blob[position : position + length]
            position += length
        else:
            raise CacheEntryError(f"protobuf-wire-type-{wire}")


def _pb_text(value: object, limit: int) -> str:
    return value.decode("utf-8", "replace").strip()[:limit] if isinstance(value, bytes) else ""


def parse_cache_storage_metadata(blob: bytes) -> dict[str, object]:
    """Service Worker ``CacheMetadata`` protobuf: request method, response status/headers/time."""
    method = ""
    status: int | None = None
    status_text = ""
    headers: dict[str, str] = {}
    names: list[str] = []
    response_time: int | None = None
    entry_time: int | None = None
    url_list: list[str] = []
    mime_type = ""
    for field, value in iter_protobuf(blob):
        if field == 1 and isinstance(value, bytes):
            for sub, sub_value in iter_protobuf(value):
                if sub == 1 and isinstance(sub_value, bytes):
                    method = _pb_text(sub_value, 16)
        elif field == 2 and isinstance(value, bytes):
            for sub, sub_value in iter_protobuf(value):
                if isinstance(sub_value, int):
                    if sub == 1:
                        status = sub_value
                    elif sub == 6:
                        response_time = sub_value
                    continue
                if sub == 2:
                    status_text = _pb_text(sub_value, 100)
                elif sub == 4:
                    pair = dict(iter_protobuf(sub_value))
                    name = _pb_text(pair.get(1), 80).lower()
                    if name and name not in names:
                        names.append(name)
                    if name in KEPT_HEADERS and name not in headers:
                        headers[name] = _pb_text(pair.get(2), 500)
                elif sub == 8 and len(url_list) < 8:
                    url_list.append(_pb_text(sub_value, 2048))
                elif sub == 13:
                    mime_type = _pb_text(sub_value, 200)
        elif field == 3 and isinstance(value, int):
            entry_time = value
    parsed = {
        "status_line": f"{status} {status_text}".strip() if status is not None else "",
        "http_version": "",
        "http_status": status,
        "headers": headers,
        "header_names": names[:80],
    }
    result = header_fields(parsed)
    if not result["content_type"] and mime_type:
        result["content_type"] = mime_type
    result.update(
        {
            "request_method": method,
            "response_time": webkit_time(response_time),
            "request_time": None,
            "original_response_time": None,
            "entry_time": webkit_time(entry_time),
            "url_list": url_list,
            "metadata_format": "cache-storage-protobuf",
        }
    )
    return result


def parse_stream0(blob: bytes) -> dict[str, object]:
    if len(blob) >= 8 and struct.unpack_from("<I", blob, 0)[0] <= len(blob) - 4 and blob.find(b"HTTP/", 0, 4096) >= 0:
        return parse_response_info_pickle(blob)
    if blob[:1] == b"\x0a":
        return parse_cache_storage_metadata(blob)
    raise CacheEntryError("stream0-unknown-format")


# --- Simple Cache ----------------------------------------------------------------------


def decode_simple_entry(path: Path) -> dict[str, object]:
    """One Simple Cache ``<hash>_0`` file → entry fields (body hashed, never kept)."""
    size = path.stat().st_size
    if size < SIMPLE_HEADER_SIZE + 2 * SIMPLE_EOF_SIZE:
        raise CacheEntryError("simple-entry-too-short")
    with path.open("rb") as handle:
        header = handle.read(SIMPLE_HEADER_SIZE)
        magic, version, key_length, key_hash = struct.unpack_from("<QIII", header, 0)
        if magic != SIMPLE_INITIAL_MAGIC:
            raise CacheEntryError("simple-entry-bad-magic")
        if key_length <= 0 or key_length > MAX_KEY_BYTES or SIMPLE_HEADER_SIZE + key_length > size:
            raise CacheEntryError("simple-entry-bad-key-length")
        key = handle.read(key_length).decode("utf-8", "replace")
        handle.seek(size - SIMPLE_EOF_SIZE)
        eof0 = handle.read(SIMPLE_EOF_SIZE)
        final_magic, flags0, _crc0, stream0_size = struct.unpack_from("<QIIi", eof0, 0)
        if final_magic != SIMPLE_FINAL_MAGIC:
            raise CacheEntryError("simple-entry-bad-eof0-magic")
        key_sha_size = 32 if flags0 & SIMPLE_EOF_FLAG_HAS_KEY_SHA256 else 0
        stream0_end = size - SIMPLE_EOF_SIZE - key_sha_size
        stream0_start = stream0_end - stream0_size
        if stream0_size < 0 or stream0_start < SIMPLE_HEADER_SIZE + key_length + SIMPLE_EOF_SIZE:
            raise CacheEntryError("simple-entry-bad-stream0-size")
        handle.seek(stream0_start - SIMPLE_EOF_SIZE)
        eof1 = handle.read(SIMPLE_EOF_SIZE)
        final_magic1, _flags1, _crc1, stream1_size = struct.unpack_from("<QIIi", eof1, 0)
        if final_magic1 != SIMPLE_FINAL_MAGIC:
            raise CacheEntryError("simple-entry-bad-eof1-magic")
        body_offset = SIMPLE_HEADER_SIZE + key_length
        if stream1_size < 0 or body_offset + stream1_size != stream0_start - SIMPLE_EOF_SIZE:
            raise CacheEntryError("simple-entry-bad-stream1-size")
        handle.seek(stream0_start)
        stream0 = handle.read(min(stream0_size, MAX_STREAM0_BYTES))
        body = body_profile_from_reader(read_chunks(handle, body_offset, stream1_size), stream1_size)
    entry: dict[str, object] = {"cache_key": key[:MAX_CACHE_KEY_CHARS], "simple_version": version, "entry_hash": f"{key_hash:08x}"}
    entry.update(parse_cache_key(key))
    if stream0:
        try:
            meta = parse_stream0(stream0)
            entry.update(meta)
            entry["headers_status"] = "parsed"
        except (CacheEntryError, struct.error, UnicodeError) as exc:
            entry["headers_status"] = f"unparsed:{exc}"[:80]
    else:
        entry["headers_status"] = "no-stream0"
    method = str(entry.get("request_method") or "")
    if method:
        entry["method"] = method.upper()
        entry["method_basis"] = "cache-storage-request"
    entry.update(body)
    entry["body_status"] = "hashed" if stream1_size else "empty"
    entry["source_offset"] = 0
    entry["body_source_offset"] = body_offset
    return entry


def decode_simple_cache_directory(directory: Path, budget: CacheBudget, *, cache_format: str) -> CacheDirectoryResult:
    result = CacheDirectoryResult(directory, cache_format)
    try:
        names = sorted(child.name for child in directory.iterdir() if SIMPLE_ENTRY_NAME.fullmatch(child.name))
    except OSError as exc:
        result.error(source_path=directory, offset=None, reason=f"directory-unreadable:{type(exc).__name__}")
        return result
    for name in names:
        if not budget.take():
            result.notes.append("entry-cap-reached")
            break
        path = directory / name
        try:
            entry = decode_simple_entry(path)
        except (CacheEntryError, struct.error, OSError, ValueError, UnicodeError) as exc:
            result.error(source_path=path, offset=0, reason=str(exc) or type(exc).__name__)
            continue
        entry["cache_format"] = cache_format
        entry["entry_file"] = str(path)
        result.entries.append(entry)
    return result


# --- blockfile ---------------------------------------------------------------------------


def addr_file_type(addr: int) -> int:
    return (addr >> 28) & 0x7


class BlockFiles:
    """Lazily opened ``data_N`` block files and ``f_XXXXXX`` external files of one directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._handles: dict[int, tuple[BinaryIO, int, int]] = {}
        self._missing: set[int] = set()

    def close(self) -> None:
        for handle, _size, _length in self._handles.values():
            handle.close()
        self._handles.clear()

    def _block_file(self, selector: int) -> tuple[BinaryIO, int, int]:
        if selector in self._handles:
            return self._handles[selector]
        name = f"data_{selector}"
        if selector in self._missing:
            raise MissingCacheFile(name)
        path = self.directory / name
        try:
            handle = path.open("rb")
        except OSError as exc:
            self._missing.add(selector)
            raise MissingCacheFile(name) from exc
        header = handle.read(BLOCK_HEADER_SIZE)
        if len(header) < 20 or struct.unpack_from("<I", header, 0)[0] != BLOCK_MAGIC:
            handle.close()
            self._missing.add(selector)
            raise CacheEntryError(f"bad-block-file-header:{name}")
        entry_size = struct.unpack_from("<i", header, 12)[0]
        if entry_size not in BLOCK_SIZES.values():
            handle.close()
            self._missing.add(selector)
            raise CacheEntryError(f"bad-block-size:{name}")
        length = path.stat().st_size
        self._handles[selector] = (handle, entry_size, length)
        return self._handles[selector]

    def block_offset(self, addr: int) -> tuple[BinaryIO, int, int]:
        """(handle, file offset, capacity in bytes) of a block-file address."""
        if not addr & ADDR_INITIALIZED or addr_file_type(addr) == FILE_TYPE_EXTERNAL:
            raise CacheEntryError(f"not-a-block-address:{addr:08x}")
        selector = (addr >> 16) & 0xFF
        start = addr & 0xFFFF
        blocks = ((addr >> 24) & 0x3) + 1
        handle, entry_size, length = self._block_file(selector)
        expected = BLOCK_SIZES.get(addr_file_type(addr))
        if expected != entry_size:
            raise CacheEntryError(f"block-size-mismatch:{addr:08x}")
        offset = BLOCK_HEADER_SIZE + start * entry_size
        capacity = blocks * entry_size
        if offset + capacity > length:
            raise CacheEntryError(f"block-beyond-file:{addr:08x}")
        return handle, offset, capacity

    def read_block(self, addr: int, size: int | None = None) -> tuple[bytes, int, str]:
        handle, offset, capacity = self.block_offset(addr)
        handle.seek(offset)
        return handle.read(min(capacity, size) if size is not None else capacity), offset, f"data_{(addr >> 16) & 0xFF}"

    def external_path(self, addr: int) -> Path:
        return self.directory / f"f_{addr & 0x0FFFFFFF:06x}"

    def read_stream(self, addr: int, size: int, limit: int) -> tuple[bytes, str, int]:
        """Up to ``limit`` bytes of a stream stored at ``addr`` (block or external file)."""
        if addr_file_type(addr) == FILE_TYPE_EXTERNAL:
            path = self.external_path(addr)
            try:
                with path.open("rb") as handle:
                    return handle.read(min(size, limit)), path.name, 0
            except OSError as exc:
                raise MissingCacheFile(path.name) from exc
        data, offset, name = self.read_block(addr, min(size, limit))
        return data, name, offset

    def stream_chunks(self, addr: int, size: int) -> tuple[Iterator[bytes], str, int]:
        if addr_file_type(addr) == FILE_TYPE_EXTERNAL:
            path = self.external_path(addr)
            try:
                handle = path.open("rb")
            except OSError as exc:
                raise MissingCacheFile(path.name) from exc

            def chunks() -> Iterator[bytes]:
                with handle:
                    yield from read_chunks(handle, 0, size)

            return chunks(), path.name, 0
        handle, offset, capacity = self.block_offset(addr)
        return read_chunks(handle, offset, min(size, capacity)), f"data_{(addr >> 16) & 0xFF}", offset


def read_index_addresses(index_path: Path) -> tuple[list[int], dict[str, object]]:
    data = index_path.read_bytes()
    if len(data) < INDEX_HEADER_SIZE or struct.unpack_from("<I", data, 0)[0] != INDEX_MAGIC:
        raise CacheEntryError("index-bad-magic")
    version = struct.unpack_from("<I", data, 4)[0]
    num_entries = struct.unpack_from("<i", data, 8)[0]
    table_len = struct.unpack_from("<i", data, 28)[0] or INDEX_DEFAULT_TABLE_LEN
    if table_len <= 0 or table_len > INDEX_MAX_TABLE_LEN:
        raise CacheEntryError("index-bad-table-length")
    available = (len(data) - INDEX_HEADER_SIZE) // 4
    count = min(table_len, available)
    table = struct.unpack_from(f"<{count}I", data, INDEX_HEADER_SIZE)
    create_time = struct.unpack_from("<Q", data, 40)[0]
    info = {
        "index_version": f"{version >> 16}.{version & 0xFFFF}",
        "index_entry_count": num_entries,
        "index_table_length": table_len,
        "index_table_truncated": count < table_len,
        "index_created_at": webkit_time(create_time),
    }
    return [addr for addr in table if addr], info


def decode_entry_store(files: BlockFiles, addr: int) -> tuple[dict[str, object], int]:
    """One ``EntryStore`` → entry fields and its ``next`` address (hash chain)."""
    block, offset, block_name = files.read_block(addr)
    if len(block) < ENTRY_STORE_SIZE:
        raise CacheEntryError("entry-store-short")
    (entry_hash, next_addr, rankings_addr, reuse_count, refetch_count, state, creation_time, key_len, long_key) = struct.unpack_from(
        "<IIIiiiQiI", block, 0
    )
    data_size = struct.unpack_from("<4i", block, 40)
    data_addr = struct.unpack_from("<4I", block, 56)
    flags = struct.unpack_from("<I", block, 72)[0]
    if key_len <= 0 or key_len > MAX_KEY_BYTES or state not in ENTRY_STATES:
        raise CacheEntryError("entry-store-implausible")
    if long_key:
        key_bytes, _name, _offset = files.read_stream(long_key, key_len, MAX_KEY_BYTES)
    else:
        if ENTRY_KEY_OFFSET + key_len > len(block):
            raise CacheEntryError("entry-store-key-beyond-blocks")
        key_bytes = block[ENTRY_KEY_OFFSET : ENTRY_KEY_OFFSET + key_len]
    key = key_bytes.decode("utf-8", "replace")
    entry: dict[str, object] = {
        "cache_key": key[:MAX_CACHE_KEY_CHARS],
        "entry_hash": f"{entry_hash:08x}",
        "entry_state": ENTRY_STATES[state],
        "reuse_count": reuse_count,
        "refetch_count": refetch_count,
        "created_at": webkit_time(creation_time),
        "source_offset": offset,
        "entry_block_file": block_name,
        "sparse_entry": bool(flags & (ENTRY_FLAG_PARENT | ENTRY_FLAG_CHILD)),
    }
    entry.update(parse_cache_key(key))
    if rankings_addr and addr_file_type(rankings_addr) == FILE_TYPE_RANKINGS:
        try:
            node, _ro, _rn = files.read_block(rankings_addr, RANKINGS_NODE_SIZE)
            if len(node) >= 16:
                last_used, last_modified = struct.unpack_from("<QQ", node, 0)
                entry["last_used_at"] = webkit_time(last_used)
                entry["last_modified_at"] = webkit_time(last_modified)
        except CacheEntryError:
            entry["rankings_status"] = "unreadable"
    # Stream 0: response metadata.
    if data_addr[0] and data_size[0] > 0:
        try:
            meta_bytes, _name, _o = files.read_stream(data_addr[0], data_size[0], MAX_STREAM0_BYTES)
            entry.update(parse_stream0(meta_bytes))
            entry["headers_status"] = "parsed"
        except MissingCacheFile as exc:
            entry["headers_status"] = f"missing-file:{exc.name}"
        except (CacheEntryError, struct.error, UnicodeError) as exc:
            entry["headers_status"] = f"unparsed:{exc}"[:80]
    else:
        entry["headers_status"] = "no-stream0"
    # Stream 1: body (hashed, never kept).
    body_size = max(data_size[1], 0)
    if entry["sparse_entry"]:
        entry.update(body_profile_from_reader(iter(()), 0))
        entry["body_size"] = body_size
        entry["body_status"] = "sparse-entry-not-hashed"
    elif data_addr[1] and body_size:
        try:
            chunks, body_file, body_offset = files.stream_chunks(data_addr[1], body_size)
            entry.update(body_profile_from_reader(chunks, body_size))
            entry["body_status"] = "hashed"
            entry["body_file"] = body_file
            entry["body_source_offset"] = body_offset
        except MissingCacheFile as exc:
            entry.update(body_profile_from_reader(iter(()), 0))
            entry["body_size"] = body_size
            entry["body_hash_scope"] = "unavailable"
            entry["body_status"] = f"missing-file:{exc.name}"
    else:
        entry.update(body_profile_from_reader(iter(()), 0))
        entry["body_status"] = "empty"
    return entry, next_addr


def decode_blockfile_directory(directory: Path, budget: CacheBudget) -> CacheDirectoryResult:
    result = CacheDirectoryResult(directory, "chromium-blockfile")
    files = BlockFiles(directory)
    try:
        try:
            addresses, info = read_index_addresses(directory / "index")
            result.notes.append(f"index-version:{info['index_version']}")
            walk = "index"
        except (CacheEntryError, OSError, struct.error) as exc:
            result.error(source_path=directory / "index", offset=0, reason=f"index-unreadable:{exc}")
            addresses = scan_entry_blocks(files)
            info = {"index_scan_fallback": True}
            walk = "data_1-scan"
        result.notes.append(f"walk:{walk}")
        seen: set[int] = set()
        for head in addresses:
            addr = head
            depth = 0
            while addr and addr not in seen and depth < MAX_CHAIN_LENGTH:
                seen.add(addr)
                depth += 1
                if not budget.take():
                    result.notes.append("entry-cap-reached")
                    return result
                try:
                    entry, next_addr = decode_entry_store(files, addr)
                except (CacheEntryError, struct.error, OSError, ValueError, UnicodeError) as exc:
                    result.error(source_path=directory / f"data_{(addr >> 16) & 0xFF}", offset=None, reason=f"{addr:08x}:{exc}")
                    break
                entry["cache_format"] = "chromium-blockfile"
                entry["cache_address"] = f"{addr:08x}"
                entry["recovery_method"] = "parsed" if walk == "index" else "carved"
                entry["entry_file"] = str(directory / str(entry.get("entry_block_file") or "data_1"))
                entry.update({key: value for key, value in info.items() if key.startswith("index_")})
                result.entries.append(entry)
                addr = next_addr if walk == "index" else 0
    finally:
        files.close()
    return result


def scan_entry_blocks(files: BlockFiles) -> list[int]:
    """Fallback when ``index`` is unusable: plausible ``EntryStore`` blocks of ``data_1``."""
    try:
        handle, entry_size, length = files._block_file(1)
    except CacheEntryError:
        return []
    if entry_size != ENTRY_STORE_SIZE:
        return []
    found: list[int] = []
    total = min((length - BLOCK_HEADER_SIZE) // ENTRY_STORE_SIZE, MAX_SCAN_BLOCKS)
    for block in range(total):
        handle.seek(BLOCK_HEADER_SIZE + block * ENTRY_STORE_SIZE)
        data = handle.read(ENTRY_STORE_SIZE)
        if len(data) < ENTRY_STORE_SIZE:
            break
        state = struct.unpack_from("<i", data, 20)[0]
        key_len = struct.unpack_from("<i", data, 32)[0]
        if state not in ENTRY_STATES or not 8 <= key_len <= ENTRY_STORE_SIZE - ENTRY_KEY_OFFSET - 1:
            continue
        key = data[ENTRY_KEY_OFFSET : ENTRY_KEY_OFFSET + key_len]
        if re.match(rb"^(\d+/\d+/)?(_dk_\S* \S* )?[a-z][a-z0-9+.-]*://", key):
            found.append(ADDR_INITIALIZED | (2 << 28) | (1 << 16) | block)
    return found


# --- directory discovery ----------------------------------------------------------------


def is_blockfile_directory(directory: Path) -> bool:
    """An ``index`` with the blockfile magic, or (index missing/damaged) a ``data_1`` block file."""
    for name, magic in (("index", INDEX_MAGIC), ("data_1", BLOCK_MAGIC)):
        try:
            with (directory / name).open("rb") as handle:
                head = handle.read(4)
        except OSError:
            continue
        if len(head) == 4 and struct.unpack("<I", head)[0] == magic:
            return True
    return False


def has_simple_entries(directory: Path) -> bool:
    try:
        return any(SIMPLE_ENTRY_NAME.fullmatch(child.name) for child in directory.iterdir())
    except OSError:
        return False


def chromium_cache_directories(profile_dir: Path, extra_roots: tuple[Path, ...] = ()) -> list[tuple[Path, str]]:
    """(directory, layout) of the HTTP and CacheStorage caches of one Chromium profile."""
    found: list[tuple[Path, str]] = []
    seen: set[str] = set()

    def add(directory: Path, layout: str) -> None:
        key = str(directory).lower()
        if key not in seen:
            seen.add(key)
            found.append((directory, layout))

    for root in (profile_dir, *extra_roots):
        for http_dir in (root / "Cache" / "Cache_Data", root / "Cache"):
            if not http_dir.is_dir():
                continue
            if is_blockfile_directory(http_dir):
                add(http_dir, "chromium-blockfile")
            elif has_simple_entries(http_dir):
                add(http_dir, "chromium-simple")
        storage = root / "Service Worker" / "CacheStorage"
        if storage.is_dir():
            try:
                origins = sorted(storage.iterdir(), key=lambda item: item.name)
            except OSError:
                origins = []
            for origin in origins:
                if not origin.is_dir():
                    continue
                try:
                    caches = sorted(origin.iterdir(), key=lambda item: item.name)
                except OSError:
                    continue
                for cache in caches:
                    if cache.is_dir() and has_simple_entries(cache):
                        add(cache, "chromium-cachestorage")
    return found


def decode_cache_directory(directory: Path, layout: str, budget: CacheBudget) -> CacheDirectoryResult:
    if layout == "chromium-blockfile":
        return decode_blockfile_directory(directory, budget)
    return decode_simple_cache_directory(directory, budget, cache_format=layout)


def file_name_from_url(url: str) -> str:
    """A file-name candidate from a URL query (``filename=`` …) or its last path segment."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    for pair in parts.query.split("&"):
        name, _, value = pair.partition("=")
        if name in FILE_NAME_QUERY_KEYS and value:
            candidate = unquote(value.replace("+", " ")).strip()
            if "." in candidate and len(candidate) <= 260:
                return candidate
    segment = unquote(parts.path.rsplit("/", 1)[-1])
    if re.fullmatch(r"[^\\/:*?\"<>|]{1,200}\.[A-Za-z0-9]{1,8}", segment or ""):
        return segment
    return ""
