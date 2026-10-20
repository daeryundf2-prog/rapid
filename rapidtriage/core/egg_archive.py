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
compressed and decompressed per member, ``MAX_ARCHIVE_DECOMPRESSED_BYTES`` per archive and a
``MAX_RATIO`` decompression-ratio guard (bombs stop with a
note). A corrupt header ends the listing with ``analysis_status`` ``*-partial`` and the
entries read so far.

Split (multi-volume) EGG (R6 S1 follow-up): every volume starts with its own EGG header whose
split extra header carries the previous / next volume's header ID (0 = none). The volumes are
linked by those IDs (siblings in the same folder; the ALZip ``name.volN.egg`` naming is used to
find candidates first and as a fallback link when the IDs do not chain), and the data after
each volume's header is read as one continuous stream (``MAX_SPLIT_VOLUMES``). A missing volume
ends the listing at the gap (``missing_volumes``, ``egg-partial``); a non-first volume lists
nothing (``egg-split-member``: the set is listed once, from its first volume). A ZIP / ALZ file
named ``.egg`` is reported as ``egg-format-mismatch`` (``format_mismatch``) instead of raising.
"""

from __future__ import annotations

import bz2
import datetime as dt
import hashlib
import lzma
import os
import re
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
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
# Decompressed bytes of one archive in total (members hashed in memory); later members are listed only.
MAX_ARCHIVE_DECOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_HASH_MEMBERS = 200
MAX_RATIO = 1000
MAX_NAME_BYTES = 4096
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
PARSER_VERSION = "egg-alz-listing-v2"
MAX_SPLIT_VOLUMES = 256
# Sibling ``.egg`` files whose headers are read to link a split set when the names do not chain.
MAX_SPLIT_SIBLING_SCAN = 1024
MAX_HEADER_EXTRAS = 64
SPLIT_NAME_RE = re.compile(r"^(?P<base>.+)\.vol(?P<number>\d{1,4})\.egg$", re.IGNORECASE)
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


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


@dataclass(frozen=True)
class _EggHeader:
    """The EGG header of one file (one volume of a split set)."""

    path: Path
    header_id: int
    split: bool
    prev_id: int
    next_id: int
    data_start: int


def _read_egg_header(path: Path) -> _EggHeader:
    """EGG header and its split extra header; raises ``ArchiveFormatError``."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        reader = _Reader(handle, size)
        if reader.u32() != EGG_SIGNATURE:
            raise ArchiveFormatError("EGG 서명(EGGA)이 아닙니다")
        reader.u16()  # version
        header_id = reader.u32()
        reader.u32()  # reserved
        split = False
        prev_id = next_id = 0
        for _ in range(MAX_HEADER_EXTRAS):
            signature = reader.u32()
            if signature == EGG_END:
                break
            _flag, data = _extra(reader)
            if signature == EGG_SPLIT:
                split = True
                if len(data) >= 8:
                    prev_id, next_id = struct.unpack_from("<II", data, 0)
        else:
            raise ArchiveFormatError("EGG 헤더 확장이 너무 많습니다")
        return _EggHeader(path, header_id, split, prev_id, next_id, reader.tell())


def sniff_format(path: Path) -> str:
    """``egg`` / ``zip`` / ``alz`` / ``""`` from the first bytes (the extension is not trusted)."""
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return ""
    if magic == b"EGGA":
        return "egg"
    if magic == ALZ_SIGNATURE:
        return "alz"
    if magic in ZIP_MAGICS:
        return "zip"
    return ""


class _VolumeStream:
    """Read-only file-like view of several volumes' regions as one continuous stream."""

    def __init__(self, parts: list[tuple[Path, int, int]]) -> None:
        self.parts = parts  # (path, start offset in the file, length)
        self.starts: list[int] = []
        total = 0
        for _path, _offset, length in parts:
            self.starts.append(total)
            total += length
        self.size = total
        self.position = 0
        self._index = -1
        self._handle = None

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = 0) -> int:
        self.position = offset if whence == 0 else self.position + offset
        return self.position

    def read(self, count: int) -> bytes:
        out = bytearray()
        while count > 0 and self.position < self.size:
            index = max(i for i, start in enumerate(self.starts) if start <= self.position)
            path, offset, length = self.parts[index]
            inside = self.position - self.starts[index]
            take = min(count, length - inside)
            if take <= 0:
                break
            if index != self._index:
                self.close()
                self._handle = path.open("rb")
                self._index = index
            self._handle.seek(offset + inside)
            chunk = self._handle.read(take)
            if not chunk:
                break
            out += chunk
            self.position += len(chunk)
            count -= len(chunk)
        return bytes(out)

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        self._index = -1


def _split_name(path: Path) -> tuple[str, int] | None:
    """``(base, N)`` of an ALZip-style ``base.volN.egg`` name."""
    match = SPLIT_NAME_RE.match(path.name)
    return (match.group("base").lower(), int(match.group("number"))) if match else None


def _split_candidates(path: Path) -> list[Path]:
    """Sibling ``.egg`` files: same ``base.volN.egg`` set first, then the rest (bounded)."""
    own = _split_name(path)
    named: list[Path] = []
    others: list[Path] = []
    try:
        with os.scandir(path.parent) as listing:
            for item in listing:
                if len(named) + len(others) >= MAX_SPLIT_SIBLING_SCAN:
                    break
                if not item.name.lower().endswith(".egg") or item.name == path.name or not item.is_file():
                    continue
                candidate = Path(item.path)
                parsed = _split_name(candidate)
                (named if own and parsed and parsed[0] == own[0] else others).append(candidate)
    except OSError:
        pass
    return sorted(named, key=lambda item: item.name.lower()) + sorted(others, key=lambda item: item.name.lower())


def _sibling_header(path: Path) -> _EggHeader | None:
    """A sibling's EGG header (``None`` when unreadable); cached by path, size and mtime so the
    volumes of one set scanned one after another do not re-read every sibling."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return _cached_header(str(path), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=4096)
def _cached_header(path: str, _size: int, _mtime_ns: int) -> _EggHeader | None:
    try:
        return _read_egg_header(Path(path))
    except (ArchiveFormatError, OSError, struct.error):
        return None


class _SplitSet:
    """The volumes of a split set around one scanned volume, linked by header IDs."""

    def __init__(self, scanned: _EggHeader) -> None:
        self.scanned = scanned
        self.base = _split_name(scanned.path)
        self.by_id: dict[int, _EggHeader] = {scanned.header_id: scanned}
        self.by_number: dict[int, _EggHeader] = {self.base[1]: scanned} if self.base else {}
        self.link = "header-id"
        self.notes: list[str] = []
        for candidate in _split_candidates(scanned.path):
            header = _sibling_header(candidate)
            if header is None or not header.split:
                continue
            self.by_id.setdefault(header.header_id, header)
            parsed = _split_name(candidate)
            if self.base and parsed and parsed[0] == self.base[0]:
                self.by_number.setdefault(parsed[1], header)

    def _neighbour(self, header: _EggHeader, step: int) -> _EggHeader | None:
        wanted = header.prev_id if step < 0 else header.next_id
        found = self.by_id.get(wanted)
        if found is not None and (found.next_id if step < 0 else found.prev_id) == header.header_id:
            return found
        parsed = _split_name(header.path)
        if parsed and self.base and parsed[0] == self.base[0] and parsed[1] + step in self.by_number:
            self.link = "file-name"
            return self.by_number[parsed[1] + step]
        return None

    def first(self) -> _EggHeader | None:
        """The first volume (``prev_id == 0``), or ``None`` when it is not in the folder."""
        current = self.scanned
        seen = {current.path}
        while current.prev_id:
            previous = self._neighbour(current, -1)
            if previous is None or previous.path in seen or len(seen) > MAX_SPLIT_VOLUMES:
                return None
            seen.add(previous.path)
            current = previous
        return current

    def chain(self, first: _EggHeader) -> tuple[list[_EggHeader], list[dict[str, object]]]:
        """Volumes from ``first`` in order, and the missing volume after the last one found."""
        volumes = [first]
        missing: list[dict[str, object]] = []
        current = first
        while current.next_id:
            if len(volumes) >= MAX_SPLIT_VOLUMES:
                self.notes.append("split-volume-cap-reached")
                break
            following = self._neighbour(current, 1)
            if following is None or following in volumes:
                missing.append(_missing_volume(current, len(volumes) + 1, current.next_id))
                break
            volumes.append(following)
            current = following
        return volumes, missing


def _missing_volume(previous: _EggHeader, position: int, header_id: int) -> dict[str, object]:
    match = SPLIT_NAME_RE.match(previous.path.name)
    expected = f"{match.group('base')}.vol{position}.egg" if match else ""
    return {"volume_index": position, "header_id": f"{header_id:08x}", "expected_name": expected}


def _mismatch_profile(fmt: str) -> dict[str, object]:
    label = fmt.upper()
    reason = f"확장자는 .egg이지만 파일 서명상 실제 형식은 {label}입니다 — {label} 도구로 확인하세요"
    return _profile("egg", "egg-format-mismatch", [], [f"format-mismatch:{fmt}"], {}, format_mismatch=fmt, reason_ko=reason)


def list_egg(path: Path, *, extract: bool = True, check_cancel: Callable[[], None] | None = None) -> dict[str, object]:
    """Entry listing of an EGG archive, split sets included (see module doc)."""
    detected = sniff_format(path)
    if detected and detected != "egg":
        return _mismatch_profile(detected)
    header = _read_egg_header(path)
    extra: dict[str, object] = {}
    missing: list[dict[str, object]] = []
    split_notes: list[str] = []
    stream: _VolumeStream | None = None
    if header.split and (header.prev_id or header.next_id):
        split_set = _SplitSet(header)
        first = split_set.first()
        if first is None or first.path != path:
            member: dict[str, object] = {
                "split_member": True,
                "split_first_volume": first.path.name if first is not None else "",
                "reason_ko": "분할 볼륨(첫 볼륨에서 목록)",
            }
            if first is None:
                member["missing_volumes"] = [{"volume_index": 1, "header_id": "", "expected_name": ""}]
                member["reason_ko"] = "분할 볼륨(첫 볼륨에서 목록) — 같은 폴더에 첫 볼륨이 없어 목록을 만들 수 없습니다"
            status = "egg-split-member" if first is not None else "egg-partial"
            return _profile("egg", status, [], ["split-member"], {"split": True}, **member)
        volumes, missing = split_set.chain(first)
        split_notes = list(split_set.notes)
        parts = [(volumes[0].path, 0, volumes[0].path.stat().st_size)]
        parts += [(volume.path, volume.data_start, volume.path.stat().st_size - volume.data_start) for volume in volumes[1:]]
        stream = _VolumeStream(parts)
        extra = {
            "split_volumes": [volume.path.name for volume in volumes],
            "volume_count": len(volumes),
            "split_link": split_set.link,
            "missing_volumes": missing,
        }
        if missing:
            names = ", ".join(str(item["expected_name"] or f"#{item['volume_index']}") for item in missing)
            extra["reason_ko"] = f"분할 볼륨 일부가 없습니다({names}) — 빠진 볼륨 앞까지만 목록을 냈습니다"
    handle = stream if stream is not None else path.open("rb")
    try:
        size = stream.size if stream is not None else path.stat().st_size
        status, entries, notes, archive = _walk_egg(_Reader(handle, size), size, extract=extract, check_cancel=check_cancel)
    finally:
        handle.close()
    notes = split_notes + notes
    if missing:
        status = "egg-partial"
        notes.append("split-volume-missing")
    elif split_notes:
        status = "egg-partial"
    return _profile("egg", status, entries, notes, archive, **extra)


def _walk_egg(
    reader: _Reader, size: int, *, extract: bool, check_cancel: Callable[[], None] | None
) -> tuple[str, list[dict[str, object]], list[str], dict[str, object]]:
    entries: list[dict[str, object]] = []
    notes: list[str] = []
    archive: dict[str, object] = {"split": False, "solid": False}
    status = "egg-parsed"
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
    return status, entries, notes, archive


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
            budget_used = int(archive.get("decompressed_bytes") or 0)
            if (
                block_compressed > MAX_MEMBER_BYTES
                or block_size > MAX_RATIO * max(block_compressed, 1)
                or len(collected) + block_size > MAX_MEMBER_BYTES
            ):
                can_extract, extract_note = False, "decompression-guard"
                reader.skip(block_compressed)
                continue
            if budget_used + block_size > MAX_ARCHIVE_DECOMPRESSED_BYTES:
                can_extract, extract_note = False, "archive-decompression-budget"
                reader.skip(block_compressed)
                continue
            archive["decompressed_bytes"] = budget_used + block_size
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


def _profile(
    fmt: str,
    status: str,
    entries: list[dict[str, object]],
    notes: list[str],
    archive: dict[str, object],
    **extra: object,
) -> dict[str, object]:
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
        **extra,
    }
