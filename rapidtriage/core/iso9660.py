"""ISO 9660 image entry listing (R5 L3; 재감사 §3 item 18).

Reads the volume descriptor set from sector 16 (ECMA-119): the Primary Volume Descriptor
(``CD001`` type 1: volume id, creation / modification times, root directory record) and, when
present, the Joliet Supplementary Volume Descriptor (type 2 with the UCS-2 escape sequence
``%/@`` / ``%/C`` / ``%/E``), whose UTF-16BE names are preferred. Directory records are walked
breadth-first: name (``;1`` version suffix removed), size, recording time (with its GMT offset),
directory / hidden flags.

UDF (``BEA01`` / ``NSR02`` / ``NSR03`` in the volume recognition sequence) is only *detected*;
a UDF-only image (no ``CD001``) gives no entries. ISO 9660 has no encryption.

Caps: ``MAX_ENTRIES`` entries, ``MAX_DIRECTORIES`` directories, ``MAX_DEPTH`` levels,
``MAX_DIRECTORY_BYTES`` per directory extent, ``MAX_TOTAL_DIRECTORY_BYTES`` per image; an
extent outside the image or a directory seen twice (loop) is skipped with a note.
"""

from __future__ import annotations

import datetime as dt
import struct
from collections import deque
from collections.abc import Callable
from pathlib import Path

SECTOR = 2048
FIRST_DESCRIPTOR_SECTOR = 16
MAX_DESCRIPTORS = 32
MAX_ENTRIES = 20_000
MAX_DIRECTORIES = 5_000
MAX_DEPTH = 24
MAX_DIRECTORY_BYTES = 8 * 1024 * 1024
# Directory extent bytes read per image in total (crafted images could repeat 8 MiB extents 5,000 times).
MAX_TOTAL_DIRECTORY_BYTES = 64 * 1024 * 1024
JOLIET_ESCAPES = (b"%/@", b"%/C", b"%/E")
UDF_IDENTIFIERS = (b"BEA01", b"NSR02", b"NSR03", b"TEA01")
PARSER_VERSION = "iso9660-listing-v1"


class IsoFormatError(ValueError):
    """Not an ISO 9660 volume (Korean message)."""


def _record_time(raw: bytes) -> str | None:
    """7-byte directory record time (years since 1900 … GMT offset in 15-minute units)."""
    if len(raw) < 7 or raw[1] == 0:
        return None
    offset = struct.unpack("b", raw[6:7])[0]
    try:
        zone = dt.timezone(dt.timedelta(minutes=15 * offset))
        return dt.datetime(1900 + raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], tzinfo=zone).isoformat()
    except ValueError:
        return None


def _volume_time(raw: bytes) -> str | None:
    """17-byte volume descriptor time ``YYYYMMDDHHMMSScc`` + GMT offset byte."""
    text = raw[:16].decode("ascii", errors="replace")
    if not text.isdigit() or text.startswith("0000"):
        return None
    offset = struct.unpack("b", raw[16:17])[0]
    try:
        zone = dt.timezone(dt.timedelta(minutes=15 * offset))
        return dt.datetime(
            int(text[0:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]), int(text[10:12]), int(text[12:14]), tzinfo=zone
        ).isoformat()
    except ValueError:
        return None


def _text(raw: bytes, joliet: bool) -> str:
    if joliet:
        return raw.decode("utf-16-be", errors="replace").rstrip(" \x00")
    return raw.decode("ascii", errors="replace").rstrip(" \x00")


def _name(raw: bytes, joliet: bool) -> str:
    name = _text(raw, joliet)
    if ";" in name:
        name = name.rsplit(";", 1)[0]
    return name.rstrip(".") if "." in name and name.endswith(".") else name


def _records(data: bytes, block: int = SECTOR) -> list[tuple[int, int, int, str | None, bytes]]:
    """``(extent, size, flags, time, name bytes)`` of the directory records of one extent."""
    out = []
    position = 0
    while position < len(data):
        length = data[position]
        if length == 0:
            position = (position // block + 1) * block  # records never span logical blocks
            continue
        record = data[position : position + length]
        if len(record) < 34 or length < 34:
            break
        extent = struct.unpack_from("<I", record, 2)[0]
        size = struct.unpack_from("<I", record, 10)[0]
        flags = record[25]
        name_length = record[32]
        out.append((extent, size, flags, _record_time(record[18:25]), record[33 : 33 + name_length]))
        position += length
    return out


def list_iso(path: Path, *, check_cancel: Callable[[], None] | None = None) -> dict[str, object]:
    """Entry listing of an ISO 9660 image (see module doc)."""
    image_size = path.stat().st_size
    notes: list[str] = []
    entries: list[dict[str, object]] = []
    with path.open("rb") as handle:
        primary: bytes | None = None
        joliet: bytes | None = None
        udf = False
        for index in range(MAX_DESCRIPTORS):
            handle.seek((FIRST_DESCRIPTOR_SECTOR + index) * SECTOR)
            descriptor = handle.read(SECTOR)
            if len(descriptor) < SECTOR:
                break
            identifier = descriptor[1:6]
            if identifier in UDF_IDENTIFIERS:
                udf = True
                continue
            if identifier != b"CD001":
                if index == 0:
                    break
                continue
            kind = descriptor[0]
            if kind == 1 and primary is None:
                primary = descriptor
            elif kind == 2 and descriptor[88:91] in JOLIET_ESCAPES and joliet is None:
                joliet = descriptor
            elif kind == 255:
                # The UDF recognition sequence follows the ISO terminator.
                continue
        if primary is None:
            if udf:
                return _profile("udf-detected-not-listed", [], ["udf-only-image"], {}, udf=True)
            raise IsoFormatError("ISO 9660 기본 볼륨 서술자(CD001)가 없습니다")
        volume = {
            "volume_id": _text(primary[40:72], False),
            "system_id": _text(primary[8:40], False),
            "volume_space_sectors": struct.unpack_from("<I", primary, 80)[0],
            "logical_block_size": struct.unpack_from("<H", primary, 128)[0],
            "publisher_id": _text(primary[318:446], False),
            "application_id": _text(primary[574:702], False),
            "created_at": _volume_time(primary[813:830]),
            "modified_at": _volume_time(primary[830:847]),
            "joliet": joliet is not None,
        }
        block = int(volume["logical_block_size"]) or SECTOR
        if block not in (512, 1024, 2048):
            raise IsoFormatError("ISO 9660 논리 블록 크기가 비정상입니다")
        descriptor = joliet if joliet is not None else primary
        is_joliet = joliet is not None
        root = descriptor[156:190]
        root_extent = struct.unpack_from("<I", root, 2)[0]
        root_size = struct.unpack_from("<I", root, 10)[0]
        queue: deque[tuple[int, int, str, int]] = deque([(root_extent, root_size, "", 0)])
        seen: set[int] = set()
        directories = 0
        directory_bytes = 0
        while queue:
            if check_cancel is not None:
                check_cancel()
            extent, size, parent, depth = queue.popleft()
            if extent in seen:
                notes.append("directory-loop-skipped")
                continue
            seen.add(extent)
            directories += 1
            if directories > MAX_DIRECTORIES:
                notes.append("directory-cap-reached")
                break
            if extent * block + size > image_size or size > MAX_DIRECTORY_BYTES:
                notes.append(f"directory-extent-out-of-range:{parent or '/'}"[:200])
                continue
            directory_bytes += size
            if directory_bytes > MAX_TOTAL_DIRECTORY_BYTES:
                notes.append("directory-read-cap-reached")
                break
            handle.seek(extent * block)
            data = handle.read(size)
            for child_extent, child_size, flags, recorded, raw_name in _records(data, block):
                if raw_name in (b"\x00", b"\x01"):
                    continue
                name = _name(raw_name, is_joliet)
                full = f"{parent}/{name}" if parent else name
                is_dir = bool(flags & 0x02)
                if len(entries) >= MAX_ENTRIES:
                    notes.append("entry-cap-reached")
                    queue.clear()
                    break
                entries.append(
                    {
                        "name": full[:500],
                        "name_encoding": "utf-16-be(joliet)" if is_joliet else "ascii(iso9660)",
                        "is_dir": is_dir,
                        "compressed_size": 0 if is_dir else child_size,
                        "uncompressed_size": 0 if is_dir else child_size,
                        "encrypted": False,
                        "hidden": bool(flags & 0x01),
                        "last_modified": recorded,
                        "timezone": "recorded-gmt-offset" if recorded else "",
                        "extent_lba": child_extent,
                        "extent_in_image": child_extent * block + child_size <= image_size,
                    }
                )
                if is_dir:
                    if depth + 1 > MAX_DEPTH:
                        notes.append("depth-cap-reached")
                    else:
                        queue.append((child_extent, child_size, full, depth + 1))
    status = "iso9660-partial" if any(note.endswith("cap-reached") for note in notes) else "iso9660-parsed"
    return _profile(status, entries, sorted(set(notes)), volume, udf=udf)


def _profile(status: str, entries: list[dict[str, object]], notes: list[str], volume: dict[str, object], *, udf: bool) -> dict[str, object]:
    total = sum(int(entry.get("uncompressed_size") or 0) for entry in entries)
    return {
        "format": "iso9660",
        "parser_version": PARSER_VERSION,
        "analysis_status": status,
        "entries": entries,
        "notes": notes,
        "volume": volume,
        "udf_present": udf,
        "header_encrypted": False,
        "total_compressed_size": total,
        "total_uncompressed_size": total,
    }
