"""EGG (ALZip 8+) and ALZ archive entry listing (R5 L3; 재감사 §3 item 9).

Pure standard library, bounded, metadata first. Layouts follow ESTsoft's published EGG format
specification (EGG header ``EGGA``, file / filename / Windows / POSIX / encrypt / split /
solid extra headers, block headers) and, for ALZ, the layout used by the open-source
``unalz`` reader (``ALZ\\x01`` archive header, ``BLZ\\x01`` local file headers, ``CLZ``
central directory).

* EGG: every file's name (UTF-8, or the locale code page the filename header names),
  uncompressed size, compressed size (sum of its blocks), modified time (Windows FILETIME
  or POSIX), attributes, encryption method, and the split / solid flags. Stored, Deflate,
  bzip2 and LZMA blocks of an *unencrypted, non-solid* archive are decompressed in memory
  (never written to disk) to check the CRC-32 and give the SHA-256 of small members;
  AZO (ESTsoft's own codec) blocks are listed only. An encrypted filename header makes the
  file list itself unreadable (``header_encrypted``).
* ALZ: names (cp949), sizes, DOS times, method, CRC and the encrypted flag; listed only.

Caps: ``MAX_ENTRIES`` entries, ``MAX_SCAN_BYTES`` of headers walked, ``MAX_MEMBER_BYTES``
decompressed per member and a ``MAX_RATIO`` decompression-ratio guard (bombs stop with a
note). A corrupt header ends the listing with ``analysis_status`` ``*-partial`` and the
entries read so far.
"""

from __future__ import annotations

import bz2
import datetime as dt
import hashlib
import lzma
import struct
import zlib
from collections.abc import Callable
from pathlib import Path

EGG_SIGNATURE = 0x41474745  # b"EGGA"
EGG_FILE = 0x0A8590E3
EGG_FILENAME = 0x0A8591AC
EGG_COMMENT = 0x04C63672
EGG_WINDOWS_INFO = 0x2C86950B
EGG_POSIX_INFO = 0x1EE922E5
EGG_ENCRYPT = 0x08D1470F
EGG_SPLIT = 0x24F5A262
EGG_SOLID = 0x24E5A060
EGG_BLOCK = 0x02B50C13
EGG_END = 0x08E28222
EGG_METHODS = {0: "store", 1: "deflate", 2: "bzip2", 3: "azo", 4: "lzma"}
EGG_ENCRYPTION = {0: "zip-2.0", 1: "aes-128", 2: "aes-256", 5: "lea-128", 6: "lea-256"}
ALZ_SIGNATURE = b"ALZ\x01"
ALZ_LOCAL = b"BLZ\x01"
ALZ_CENTRAL = b"CLZ\x01"
ALZ_END = b"CLZ\x02"
ALZ_METHODS = {0: "store", 1: "bzip2", 2: "deflate"}
MAX_ENTRIES = 20_000
MAX_SCAN_BYTES = 4 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_HASH_MEMBERS = 200
MAX_RATIO = 1000
MAX_NAME_BYTES = 4096
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
PARSER_VERSION = "egg-alz-listing-v1"


class ArchiveFormatError(ValueError):
    """The bytes are not a well-formed EGG / ALZ structure (Korean message)."""


def _filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)).isoformat().replace("+00:00", "Z")
    except OverflowError:
        return None


def _dos_time(value: int) -> str | None:
    date, time = value >> 16, value & 0xFFFF
    try:
        moment = dt.datetime(
            1980 + (date >> 9), (date >> 5) & 0x0F, date & 0x1F, time >> 11, (time >> 5) & 0x3F, (time & 0x1F) * 2
        )
    except ValueError:
        return None
    return moment.isoformat()


class _Reader:
    """Bounded little-endian reader over a file handle."""

    def __init__(self, handle, size: int) -> None:
        self.handle = handle
        self.size = size

    def tell(self) -> int:
        return self.handle.tell()

    def read(self, count: int) -> bytes:
        if count < 0 or self.tell() + count > self.size:
            raise ArchiveFormatError("헤더가 파일 끝을 넘습니다(잘린 압축 파일)")
        data = self.handle.read(count)
        if len(data) != count:
            raise ArchiveFormatError("헤더를 끝까지 읽지 못했습니다")
        return data

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def skip(self, count: int) -> None:
        if count < 0 or self.tell() + count > self.size:
            raise ArchiveFormatError("데이터 길이가 파일 끝을 넘습니다(잘린 압축 파일)")
        self.handle.seek(count, 1)


def _extra(reader: _Reader) -> tuple[int, bytes]:
    """``(bit flag, data)`` of an EGG extra header after its signature (bit 0: 4-byte size)."""
    flag = reader.u8()
    size = reader.u32() if flag & 0x01 else reader.u16()
    if size > 16 * 1024 * 1024:
        raise ArchiveFormatError("확장 헤더 크기가 비정상입니다")
    return flag, reader.read(size)


def _decode_name(raw: bytes, locale: int | None) -> tuple[str, str]:
    raw = raw[:MAX_NAME_BYTES]
    if locale is None:
        try:
            return raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass
    codepage = {949: "cp949", 932: "cp932", 936: "gbk", 950: "cp950", 1252: "cp1252"}.get(locale or 949, "cp949")
    return raw.decode(codepage, errors="replace"), codepage


def _decompress(method: str, data: bytes, expected: int) -> bytes:
    """One EGG block's data (``expected`` bytes); raises ``ValueError`` past the caps."""
    if expected > MAX_MEMBER_BYTES:
        raise ValueError("member-too-large")
    if method == "store":
        return data
    if method == "deflate":
        decoder = zlib.decompressobj(-15)
        out = decoder.decompress(data, expected + 1)
    elif method == "bzip2":
        out = bz2.BZ2Decompressor().decompress(data, expected + 1)
    elif method == "lzma":
        out = _lzma_block(data, expected)
    else:
        raise ValueError("unsupported-method")
    if len(out) > expected:
        raise ValueError("decompressed-larger-than-header")
    return out


def _lzma_block(data: bytes, expected: int) -> bytes:
    """EGG LZMA block: a 4-byte prefix, the 5-byte LZMA properties, then the raw stream
    (also tried with the properties first; the layout is not confirmed on a real sample)."""
    for offset in (4, 0):
        filters = _lzma1_filters(data[offset : offset + 5])
        if filters is None:
            continue
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
            out = decoder.decompress(data[offset + 5 :], expected + 1)
        except (lzma.LZMAError, ValueError):
            continue
        if len(out) == expected:
            return out
    raise ValueError("lzma-decode-failed")


def _lzma1_filters(props: bytes) -> list[dict[str, int]] | None:
    """Raw LZMA1 filter chain of the 5 classic properties bytes (``lc/lp/pb`` byte + dictionary size)."""
    if len(props) < 5 or props[0] >= 9 * 5 * 5:
        return None
    value = props[0]
    dict_size = struct.unpack_from("<I", props, 1)[0]
    if not 4096 <= dict_size <= 1 << 30:
        return None
    return [{"id": lzma.FILTER_LZMA1, "lc": value % 9, "lp": (value // 9) % 5, "pb": value // 45, "dict_size": dict_size}]


def _entry(name: str, **fields: object) -> dict[str, object]:
    return {"name": name[:500], **fields}


def list_egg(path: Path, *, extract: bool = True, check_cancel: Callable[[], None] | None = None) -> dict[str, object]:
    """Entry listing of an EGG archive (see module doc)."""
    size = path.stat().st_size
    entries: list[dict[str, object]] = []
    notes: list[str] = []
    archive: dict[str, object] = {"split": False, "solid": False}
    status = "egg-parsed"
    with path.open("rb") as handle:
        reader = _Reader(handle, size)
        if reader.u32() != EGG_SIGNATURE:
            raise ArchiveFormatError("EGG 서명(EGGA)이 아닙니다")
        archive["version"] = reader.u16()
        reader.u32()  # header id (random)
        reader.u32()  # reserved
        while True:
            signature = reader.u32()
            if signature == EGG_END:
                break
            _extra(reader)
            if signature == EGG_SPLIT:
                archive["split"] = True
            elif signature == EGG_SOLID:
                archive["solid"] = True
        hashed = 0
        try:
            while reader.tell() < min(size, MAX_SCAN_BYTES):
                if check_cancel is not None and len(entries) % 200 == 0:
                    check_cancel()
                signature = reader.u32()
                if signature == EGG_END:
                    break
                if signature == EGG_COMMENT:
                    _extra(reader)
                    continue
                if signature != EGG_FILE:
                    raise ArchiveFormatError(f"알 수 없는 EGG 헤더 서명 0x{signature:08x}")
                if len(entries) >= MAX_ENTRIES:
                    notes.append("entry-cap-reached")
                    status = "egg-partial"
                    break
                entry, hashed = _egg_file(reader, archive, extract=extract, hashed=hashed)
                entries.append(entry)
        except ArchiveFormatError as exc:
            status = "egg-partial"
            notes.append(f"corrupt: {exc}"[:200])
    return _profile("egg", status, entries, notes, archive)


def _egg_file(reader: _Reader, archive: dict[str, object], *, extract: bool, hashed: int) -> tuple[dict[str, object], int]:
    reader.u32()  # file id
    uncompressed = reader.u64()
    name = ""
    name_encoding = ""
    name_encrypted = False
    modified: str | None = None
    attributes = 0
    encryption = ""
    while True:
        signature = reader.u32()
        if signature == EGG_END:
            break
        flag, data = _extra(reader)
        if signature == EGG_FILENAME:
            name_encrypted = bool(flag & 0x08)
            position = 0
            locale = None
            if flag & 0x10:
                locale = struct.unpack_from("<H", data, position)[0]
                position += 2
            if flag & 0x20:
                position += 4  # parent path id
            if name_encrypted:
                name, name_encoding = "", "encrypted"
            else:
                name, name_encoding = _decode_name(data[position:], locale)
        elif signature == EGG_WINDOWS_INFO and len(data) >= 9:
            modified = _filetime(struct.unpack_from("<Q", data, 0)[0])
            attributes = data[8]
        elif signature == EGG_POSIX_INFO and len(data) >= 20:
            moment = struct.unpack_from("<Q", data, 12)[0]
            if 0 < moment < 4_102_444_800:
                modified = dt.datetime.fromtimestamp(moment, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        elif signature == EGG_ENCRYPT and data:
            encryption = EGG_ENCRYPTION.get(data[0], f"unknown-{data[0]}")
    compressed = 0
    crc_ok: bool | None = None
    digest = None
    methods: list[str] = []
    collected = bytearray()
    can_extract = extract and not encryption and not archive.get("solid") and uncompressed <= MAX_MEMBER_BYTES and hashed < MAX_HASH_MEMBERS
    extract_note = ""
    while True:
        position = reader.tell()
        signature = reader.u32()
        if signature != EGG_BLOCK:
            reader.handle.seek(position)
            break
        method = EGG_METHODS.get(reader.u8(), "unknown")
        reader.u8()  # compression hint
        block_size = reader.u32()
        block_compressed = reader.u32()
        block_crc = reader.u32()
        if reader.u32() != EGG_END:
            raise ArchiveFormatError("블록 헤더 끝 표시가 없습니다")
        compressed += block_compressed
        if method not in methods:
            methods.append(method)
        if can_extract and method in ("store", "deflate", "bzip2", "lzma"):
            if block_size > MAX_RATIO * max(block_compressed, 1) or len(collected) + block_size > MAX_MEMBER_BYTES:
                can_extract, extract_note = False, "decompression-guard"
                reader.skip(block_compressed)
                continue
            data = reader.read(block_compressed)
            try:
                out = _decompress(method, data, block_size)
            except (ValueError, OSError, EOFError, zlib.error, lzma.LZMAError) as exc:
                can_extract, extract_note = False, f"decompress-failed:{exc}"[:120]
                continue
            crc_ok = (zlib.crc32(out) & 0xFFFFFFFF) == block_crc and (crc_ok is not False)
            collected.extend(out)
        else:
            if can_extract and method not in ("store", "deflate", "bzip2", "lzma"):
                can_extract, extract_note = False, f"list-only-method:{method}"
            reader.skip(block_compressed)
    if can_extract and len(collected) == uncompressed and crc_ok is not None:
        digest = hashlib.sha256(bytes(collected)).hexdigest()
        hashed += 1
    is_dir = bool(attributes & 0x80)
    entry = _entry(
        name,
        name_encoding=name_encoding,
        is_dir=is_dir,
        compressed_size=compressed,
        uncompressed_size=uncompressed,
        compression_methods=methods,
        encrypted=bool(encryption),
        encryption_method=encryption,
        name_encrypted=name_encrypted,
        last_modified=modified,
        timezone="UTC" if modified else "",
        attributes=attributes,
        crc_ok=crc_ok,
        sha256=digest,
        extract_note=extract_note or ("encrypted-not-extracted" if encryption else ""),
    )
    return entry, hashed


def list_alz(path: Path, *, check_cancel: Callable[[], None] | None = None) -> dict[str, object]:
    """Entry listing of an ALZ archive (list only; see module doc)."""
    size = path.stat().st_size
    entries: list[dict[str, object]] = []
    notes: list[str] = []
    status = "alz-parsed"
    with path.open("rb") as handle:
        reader = _Reader(handle, size)
        if reader.read(4) != ALZ_SIGNATURE:
            raise ArchiveFormatError("ALZ 서명(ALZ\\x01)이 아닙니다")
        reader.skip(4)
        try:
            while reader.tell() < min(size, MAX_SCAN_BYTES):
                if check_cancel is not None and len(entries) % 200 == 0:
                    check_cancel()
                signature = reader.read(4)
                if signature in (ALZ_CENTRAL, ALZ_END):
                    break
                if signature != ALZ_LOCAL:
                    raise ArchiveFormatError(f"알 수 없는 ALZ 헤더 서명 {signature.hex()}")
                if len(entries) >= MAX_ENTRIES:
                    notes.append("entry-cap-reached")
                    status = "alz-partial"
                    break
                name_length = reader.u16()
                attributes = reader.u8()
                time_date = reader.u32()
                descriptor = reader.u8()
                reader.u8()
                size_bytes = descriptor >> 4
                method = ""
                crc = None
                compressed = uncompressed = 0
                if size_bytes:
                    if size_bytes not in (1, 2, 4, 8):
                        raise ArchiveFormatError("ALZ 크기 필드 길이가 비정상입니다")
                    method = ALZ_METHODS.get(reader.u8(), "unknown")
                    reader.u8()
                    crc = reader.u32()
                    compressed = int.from_bytes(reader.read(size_bytes), "little")
                    uncompressed = int.from_bytes(reader.read(size_bytes), "little")
                if name_length > MAX_NAME_BYTES:
                    raise ArchiveFormatError("ALZ 파일 이름 길이가 비정상입니다")
                name = reader.read(name_length).decode("cp949", errors="replace")
                encrypted = bool(descriptor & 0x01)
                if encrypted:
                    reader.skip(12)
                reader.skip(compressed)
                entries.append(
                    _entry(
                        name,
                        name_encoding="cp949",
                        is_dir=bool(attributes & 0x10),
                        compressed_size=compressed,
                        uncompressed_size=uncompressed,
                        compression_methods=[method] if method else [],
                        encrypted=encrypted,
                        encryption_method="zip-2.0" if encrypted else "",
                        name_encrypted=False,
                        last_modified=_dos_time(time_date),
                        timezone="local-unknown",
                        attributes=attributes,
                        crc32=f"{crc:08x}" if crc is not None else "",
                        crc_ok=None,
                        sha256=None,
                        extract_note="list-only-format",
                    )
                )
        except ArchiveFormatError as exc:
            status = "alz-partial"
            notes.append(f"corrupt: {exc}"[:200])
    return _profile("alz", status, entries, notes, {})


def _profile(fmt: str, status: str, entries: list[dict[str, object]], notes: list[str], archive: dict[str, object]) -> dict[str, object]:
    total_compressed = sum(int(entry.get("compressed_size") or 0) for entry in entries)
    total_uncompressed = sum(int(entry.get("uncompressed_size") or 0) for entry in entries)
    return {
        "format": fmt,
        "parser_version": PARSER_VERSION,
        "analysis_status": status,
        "entries": entries,
        "notes": notes,
        "split": bool(archive.get("split")),
        "solid": bool(archive.get("solid")),
        "header_encrypted": any(entry.get("name_encrypted") for entry in entries),
        "total_compressed_size": total_compressed,
        "total_uncompressed_size": total_uncompressed,
    }
