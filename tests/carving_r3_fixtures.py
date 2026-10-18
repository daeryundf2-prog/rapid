"""Synthetic carving fixtures for the R3 signatures (plan r3-os-depth §3.3 / Q-R3-6).

Every builder returns the bytes of one well-formed file of the format; the
tests embed them in slack-like padding and also truncate / corrupt them.
Nothing here is real evidence: structures are generated from the format
specifications.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib


def wav(data_bytes: int = 4000) -> bytes:
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", data_bytes) + b"\x01\x02" * (data_bytes // 2)
    return b"RIFF" + struct.pack("<I", len(body)) + body


MP3_FRAME_HEADER = b"\xff\xfb\x90\x00"  # MPEG-1 Layer III, 128 kbps, 44.1 kHz, no padding
MP3_FRAME_LENGTH = 417


def mp3_frames(count: int) -> bytes:
    return (MP3_FRAME_HEADER + b"\x11" * (MP3_FRAME_LENGTH - 4)) * count


def mp3_id3(frames: int = 12) -> bytes:
    tag_body = b"TIT2" + struct.pack(">I", 6) + b"\x00\x00" + b"\x00title"
    size = len(tag_body)
    syncsafe = bytes(((size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F))
    return b"ID3\x03\x00\x00" + syncsafe + tag_body + mp3_frames(frames)


def _box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def bmff(major: bytes, compatible: tuple[bytes, ...] = (b"isom",)) -> bytes:
    ftyp = _box(b"ftyp", major + b"\x00\x00\x02\x00" + b"".join(compatible))
    moov = _box(b"moov", _box(b"mvhd", b"\x00" * 100))
    mdat = _box(b"mdat", b"\x22" * 2048)
    return ftyp + moov + mdat


def m4a() -> bytes:
    return bmff(b"M4A ", (b"M4A ", b"mp42", b"isom"))


def mp4() -> bytes:
    return bmff(b"isom", (b"isom", b"iso2", b"avc1", b"mp41"))


_OOXML_MAIN = {
    "docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"),
    "xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"),
    "pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"),
}


def ooxml(kind: str, *, with_app_part: bool = True) -> bytes:
    part, content_type = _OOXML_MAIN[kind]
    types = (
        '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'<Override PartName="/{part}" ContentType="{content_type}"/></Types>'
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", types)
        archive.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        if with_app_part:
            archive.writestr(part, "<doc>" + "본문 " * 200 + "</doc>")
            archive.writestr(part.split("/")[0] + "/styles.xml", "<styles/>")
    return buffer.getvalue()


def hwpx(*, with_contents: bool = True) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo("mimetype"), "application/hwp+zip", compress_type=zipfile.ZIP_STORED)
        archive.writestr("version.xml", "<version/>")
        if with_contents:
            archive.writestr("Contents/content.hpf", "<opf/>")
            archive.writestr("Contents/section0.xml", "<sec>" + "한글 " * 100 + "</sec>")
    return buffer.getvalue()


def plain_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", "alpha " * 50)
        archive.writestr("b.txt", "beta " * 50)
    return buffer.getvalue()


FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD


def _dir_entry(name: str, kind: int, start: int, size: int, child: int = FREESECT) -> bytes:
    encoded = (name + "\x00").encode("utf-16le")
    entry = bytearray(128)
    entry[: len(encoded)] = encoded
    struct.pack_into("<HBB", entry, 0x40, len(encoded), kind, 1)
    struct.pack_into("<III", entry, 0x44, FREESECT, FREESECT, child)
    struct.pack_into("<IQ", entry, 0x74, start, size)
    return bytes(entry)


def ole(stream_name: str = "FileHeader", content: bytes = b"HWP Document File" + b"\x00" * 15) -> bytes:
    """A version-3 compound file: FAT (sector 0), directory (1), mini FAT (2), mini stream (3)."""
    content = content.ljust(256, b"\x00")
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 0x28, 0, 1, 1, 0, 4096, 2, 1, ENDOFCHAIN, 0)
    difat = [0] + [FREESECT] * 108
    struct.pack_into("<109I", header, 0x4C, *difat)
    fat = [FATSECT, ENDOFCHAIN, ENDOFCHAIN, ENDOFCHAIN] + [FREESECT] * 124
    directory = (
        _dir_entry("Root Entry", 5, 3, len(content), child=1)
        + _dir_entry(stream_name, 2, 0, len(content))
        + b"\x00" * 256
    )
    minifat = [1, 2, 3, ENDOFCHAIN] + [FREESECT] * 124
    return (
        bytes(header)
        + struct.pack("<128I", *fat)
        + directory
        + struct.pack("<128I", *minifat)
        + content.ljust(512, b"\x00")
    )


def hwp() -> bytes:
    return ole()


EML = (
    b"Return-Path: <alice@example.test>\r\n"
    b"Received: from mx.example.test by mail.example.test; Tue, 1 Oct 2024 09:00:00 +0900\r\n"
    b"From: Alice <alice@example.test>\r\n"
    b"To: Bob <bob@example.test>\r\n"
    b"Subject: =?UTF-8?B?7ZqM7J2Y?=\r\n"
    b"Date: Tue, 1 Oct 2024 09:00:00 +0900\r\n"
    b"Message-ID: <r3-carve@example.test>\r\n"
    b"\r\n"
    b"Synthetic body line.\r\n"
)


def pe(*, sections: int = 2) -> bytes:
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, sections, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)  # section / file alignment
    struct.pack_into("<I", data, optional + 60, 0x400)  # SizeOfHeaders
    table = optional + 240
    for index, (name, pointer) in enumerate(((b".text", 0x400), (b".data", 0x600))[:sections]):
        entry = bytearray(40)
        entry[: len(name)] = name
        struct.pack_into("<IIII", entry, 8, 0x200, 0x1000 * (index + 1), 0x200, pointer)
        data[table + 40 * index : table + 40 * index + 40] = entry
    data[0x400:0x404] = b"\xcc\xcc\xcc\xc3"
    return bytes(data)


def evtx(chunks: int = 1) -> bytes:
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQIHHHH", header, 8, 0, chunks - 1, 1, 128, 1, 3, 4096, chunks)
    struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[:120])) & 0xFFFFFFFF)
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    return bytes(header) + bytes(chunk) * chunks


def slack(*parts: bytes, gap: int = 1024) -> bytes:
    """Parts separated by 0xE5 filler (FAT-style slack) so no part touches another."""
    filler = b"\xe5" * gap
    return filler + filler.join(parts) + filler
