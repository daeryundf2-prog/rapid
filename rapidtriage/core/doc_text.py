"""Native (stdlib) text extraction for binary office formats and PDF.

Parser-quality r1 (findings Major 5/6). Every extractor returns a
:class:`DocumentText` with the text plus an honest status:

* ``ok`` - text extracted;
* ``encrypted`` - the document is password/DRM protected (``encrypted=True``,
  any unencrypted preview text such as HWP ``PrvText`` is kept);
* ``no-text`` - parsed, but the document holds no extractable text
  (scanned PDF, empty document) - ``reason`` says why;
* ``binary-rejected`` - the decoded text was mostly non-printable and was
  dropped rather than indexed as noise;
* ``unsupported`` / ``error`` - format variant not handled / parse failure.

Formats: HWP 5.0 (OLE: FileHeader flags, BodyText/Section* raw-deflate,
record headers, HWPTAG_PARA_TEXT UTF-16LE with control characters
stripped; PrvText fallback), HWPX (zip ``Contents/section*.xml``), OLE2
Word ``.doc`` (FIB + piece table in 0Table/1Table; text-run fallback),
Excel ``.xls`` (BIFF8 SST/LABEL/BOUNDSHEET with CONTINUE handling),
PowerPoint ``.ppt`` (TextCharsAtom/TextBytesAtom) and PDF (indirect
objects + object streams, FlateDecode, page content streams
Tj/TJ/'/" with ToUnicode CMaps bfchar/bfrange and simple encodings; image
and font streams skipped).
"""

from __future__ import annotations

import re
import struct
import zipfile
import zlib
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from .safe_xml import safe_xml_fromstring

__all__ = [
    "DocumentText",
    "OleError",
    "OleFile",
    "clean_extracted_text",
    "extract_doc_text",
    "extract_hwp_text",
    "extract_hwpx_text",
    "extract_pdf_document_text",
    "extract_ppt_text",
    "extract_xls_text",
    "hwp_para_text",
    "iter_hwp_records",
    "printable_ratio",
]

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_BINARY_RATIO = 0.20
MAX_DECOMPRESSED_STREAM_BYTES = 64 * 1024 * 1024


@dataclass
class DocumentText:
    text: str
    status: str = "ok"
    method: str = ""
    encrypted: bool = False
    reason: str = ""
    warnings: list[str] = field(default_factory=list)

    def as_metadata(self) -> dict[str, object]:
        meta: dict[str, object] = {
            "text_status": self.status,
            "extraction_method": self.method,
            "encrypted": self.encrypted,
            "text_length": len(self.text),
        }
        if self.reason:
            meta["text_reason"] = self.reason
        if self.warnings:
            meta["text_warnings"] = list(self.warnings[:10])
        return meta


# --- text hygiene -----------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f￾￿﻿]")
_SPACE_RUN_RE = re.compile(r"[ \t]{2,}")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


def printable_ratio(text: str) -> float:
    if not text:
        return 1.0
    bad = sum(
        1
        for char in text
        if (ord(char) < 32 and char not in "\n\r\t") or 0xE000 <= ord(char) <= 0xF8FF or char in "�￾￿"
    )
    return 1.0 - bad / len(text)


def clean_extracted_text(text: str) -> str:
    """Strip control characters and collapse whitespace runs."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub(" ", text)
    text = _SPACE_RUN_RE.sub(" ", text)
    return _BLANK_LINES_RE.sub("\n\n", text).strip()


def finalize(text: str, *, method: str, encrypted: bool = False, empty_reason: str = "", warnings: list[str] | None = None) -> DocumentText:
    ratio = printable_ratio(text)
    if text and ratio < 1.0 - MAX_BINARY_RATIO:
        return DocumentText(
            "",
            status="binary-rejected",
            method=method,
            encrypted=encrypted,
            reason=f"비인쇄 문자 비율 {1.0 - ratio:.0%} > {MAX_BINARY_RATIO:.0%}: 바이너리 본문으로 판단해 색인하지 않음",
            warnings=list(warnings or []),
        )
    cleaned = clean_extracted_text(text)
    if encrypted:
        return DocumentText(
            cleaned,
            status="encrypted",
            method=method,
            encrypted=True,
            reason=empty_reason or "암호화/배포용 문서: 본문 복호화 불가",
            warnings=list(warnings or []),
        )
    if not cleaned:
        return DocumentText("", status="no-text", method=method, reason=empty_reason or "추출 가능한 텍스트 없음", warnings=list(warnings or []))
    return DocumentText(cleaned, status="ok", method=method, warnings=list(warnings or []))


# --- OLE2 / CFB reader --------------------------------------------------------


class OleError(ValueError):
    pass


_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_MAX_SECT = 0xFFFFFFFA


class OleFile:
    """Minimal read-only Compound File Binary reader (MS-CFB)."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 512 or not data.startswith(OLE_SIGNATURE):
            raise OleError("not an OLE2 compound file")
        self.data = data
        sector_shift = struct.unpack_from("<H", data, 0x1E)[0]
        mini_shift = struct.unpack_from("<H", data, 0x20)[0]
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise OleError("unsupported OLE sector size")
        self.sector_size = 1 << sector_shift
        self.mini_sector_size = 1 << mini_shift
        num_fat = struct.unpack_from("<I", data, 0x2C)[0]
        first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self.mini_cutoff = struct.unpack_from("<I", data, 0x38)[0]
        first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        first_difat = struct.unpack_from("<I", data, 0x44)[0]
        num_difat = struct.unpack_from("<I", data, 0x48)[0]
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        sector = first_difat
        guard = 0
        while sector < _MAX_SECT and guard < num_difat + 1 and guard < 100_000:
            raw = self._sector(sector)
            entries = struct.unpack(f"<{self.sector_size // 4}I", raw)
            difat.extend(entries[:-1])
            sector = entries[-1]
            guard += 1
        fat_sectors = [item for item in difat if item < _MAX_SECT][:num_fat or None]
        fat_bytes = b"".join(self._sector(item) for item in fat_sectors)
        self.fat = list(struct.unpack(f"<{len(fat_bytes) // 4}I", fat_bytes))
        dir_bytes = self._chain_bytes(first_dir, self.fat, self.sector_size, self._sector)
        self.entries: list[dict[str, object]] = []
        for offset in range(0, len(dir_bytes) - 127, 128):
            raw = dir_bytes[offset : offset + 128]
            name_len = struct.unpack_from("<H", raw, 0x40)[0]
            name = raw[: max(0, name_len - 2)].decode("utf-16le", errors="replace")
            entry_type = raw[0x42]
            left, right, child = struct.unpack_from("<III", raw, 0x44)
            start = struct.unpack_from("<I", raw, 0x74)[0]
            size = struct.unpack_from("<Q", raw, 0x78)[0]
            if self.sector_size == 512:
                size &= 0xFFFFFFFF
            self.entries.append(
                {"name": name, "type": entry_type, "left": left, "right": right, "child": child, "start": start, "size": size}
            )
        if not self.entries:
            raise OleError("empty OLE directory")
        root = self.entries[0]
        self.ministream = self._chain_bytes(int(root["start"]), self.fat, self.sector_size, self._sector)[: int(root["size"])]
        minifat_bytes = self._chain_bytes(first_minifat, self.fat, self.sector_size, self._sector) if first_minifat < _MAX_SECT else b""
        self.minifat = list(struct.unpack(f"<{len(minifat_bytes) // 4}I", minifat_bytes))
        self.paths = self._build_paths()

    def _sector(self, index: int) -> bytes:
        offset = (index + 1) * self.sector_size
        chunk = self.data[offset : offset + self.sector_size]
        if len(chunk) < self.sector_size:
            chunk = chunk.ljust(self.sector_size, b"\x00")
        return chunk

    def _mini_sector(self, index: int) -> bytes:
        offset = index * self.mini_sector_size
        return self.ministream[offset : offset + self.mini_sector_size]

    @staticmethod
    def _chain_bytes(start: int, table: Sequence[int], size: int, reader) -> bytes:  # type: ignore[no-untyped-def]
        chunks: list[bytes] = []
        seen: set[int] = set()
        sector = start
        while sector < _MAX_SECT and sector < len(table) + 1 and sector not in seen:
            seen.add(sector)
            chunks.append(reader(sector))
            if sector >= len(table):
                break
            sector = table[sector]
        return b"".join(chunks)

    def _build_paths(self) -> dict[str, int]:
        paths: dict[str, int] = {}

        def visit(index: int, prefix: str, depth: int) -> None:
            stack = [index]
            seen: set[int] = set()
            while stack:
                current = stack.pop()
                if current >= len(self.entries) or current in seen or current == _FREESECT:
                    continue
                seen.add(current)
                entry = self.entries[current]
                name = str(entry["name"])
                full = f"{prefix}{name}"
                paths[full.lower()] = current
                if entry["type"] == 1 and depth < 32:  # storage
                    visit(int(entry["child"]), f"{full}/", depth + 1)
                stack.append(int(entry["left"]))
                stack.append(int(entry["right"]))

        visit(int(self.entries[0]["child"]), "", 0)
        return paths

    def exists(self, path: str) -> bool:
        return path.lower() in self.paths

    def list_streams(self) -> list[str]:
        return sorted(name for name, index in self.paths.items() if self.entries[index]["type"] == 2)

    def read(self, path: str) -> bytes:
        index = self.paths.get(path.lower())
        if index is None:
            raise OleError(f"OLE stream not found: {path}")
        entry = self.entries[index]
        size = int(entry["size"])
        start = int(entry["start"])
        if size < self.mini_cutoff:
            data = self._chain_bytes(start, self.minifat, self.mini_sector_size, self._mini_sector)
        else:
            data = self._chain_bytes(start, self.fat, self.sector_size, self._sector)
        return data[:size]


def open_ole(path: Path) -> OleFile:
    return OleFile(path.read_bytes())


# --- HWP 5.0 ------------------------------------------------------------------

HWPTAG_BEGIN = 0x10
HWPTAG_PARA_TEXT = HWPTAG_BEGIN + 51
_HWP_CHAR_CONTROLS = frozenset({0, 10, 13, *range(24, 32)})


def iter_hwp_records(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(tag_id, level, payload)`` from an HWP record stream."""
    offset = 0
    length = len(data)
    while offset + 4 <= length:
        header = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        tag = header & 0x3FF
        level = (header >> 10) & 0x3FF
        size = (header >> 20) & 0xFFF
        if size == 0xFFF:
            if offset + 4 > length:
                return
            size = struct.unpack_from("<I", data, offset)[0]
            offset += 4
        payload = data[offset : offset + size]
        offset += size
        yield tag, level, payload


def hwp_para_text(payload: bytes) -> str:
    """Decode HWPTAG_PARA_TEXT (UTF-16LE) dropping inline/extended controls.

    Char controls (1 WCHAR): 0, 10 (line break), 13 (paragraph end), 24-31.
    Inline/extended controls (codes 1-9, 11, 12, 14-23) occupy 8 WCHARs.
    """
    out: list[str] = []
    count = len(payload) // 2
    index = 0
    while index < count:
        code = payload[index * 2] | (payload[index * 2 + 1] << 8)
        if code >= 32:
            if 0xD800 <= code <= 0xDBFF and index + 1 < count:
                low = payload[index * 2 + 2] | (payload[index * 2 + 3] << 8)
                out.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)) if 0xDC00 <= low <= 0xDFFF else " ")
                index += 2
                continue
            out.append(chr(code))
            index += 1
            continue
        if code in _HWP_CHAR_CONTROLS:
            if code in (10, 13):
                out.append("\n")
            elif code in (30, 31):
                out.append(" ")
            index += 1
            continue
        if code == 9:
            out.append("\t")
        index += 8
    return "".join(out)


class TextTooLarge(ValueError):
    """A stream inflates past the extraction limit (docs.TextExtractionTooLarge)."""


def _inflate(data: bytes, *, raw: bool, limit: int = MAX_DECOMPRESSED_STREAM_BYTES, label: str = "") -> bytes:
    decompressor = zlib.decompressobj(-15 if raw else 15)
    out = decompressor.decompress(data, limit + 1 if limit > 0 else 0)
    if limit > 0 and (len(out) > limit or decompressor.unconsumed_tail):
        if label:
            raise TextTooLarge(f"{label} expands beyond text extraction size limit")
        return out[:limit]
    return out


def _hwp_section_text(stream: bytes, compressed: bool) -> str:
    data = stream
    if compressed:
        try:
            data = _inflate(stream, raw=True)
        except zlib.error:
            data = _inflate(stream, raw=False)
    parts = [hwp_para_text(payload) for tag, _level, payload in iter_hwp_records(data) if tag == HWPTAG_PARA_TEXT]
    return "".join(parts)


def extract_hwp_text(path: Path) -> DocumentText:
    try:
        ole = open_ole(path)
    except OleError as exc:
        return DocumentText("", status="unsupported", method="hwp5-ole", reason=f"HWP 5.0(OLE) 형식 아님: {exc}")
    if not ole.exists("FileHeader"):
        return DocumentText("", status="unsupported", method="hwp5-ole", reason="FileHeader 스트림 없음")
    header = ole.read("FileHeader")
    if not header.startswith(b"HWP Document File"):
        return DocumentText("", status="unsupported", method="hwp5-ole", reason="HWP 시그니처 불일치")
    flags = struct.unpack_from("<I", header, 36)[0] if len(header) >= 40 else 0
    compressed = bool(flags & 0x1)
    password = bool(flags & 0x2)
    distribution = bool(flags & 0x4)
    warnings: list[str] = []
    sections = sorted(
        (name for name in ole.list_streams() if name.startswith("bodytext/section")),
        key=lambda name: int(re.sub(r"\D", "", name.rsplit("/", 1)[-1]) or 0),
    )
    texts: list[str] = []
    if not password and not distribution:
        for name in sections:
            try:
                texts.append(_hwp_section_text(ole.read(name), compressed))
            except (zlib.error, OleError, struct.error) as exc:
                warnings.append(f"{name}: {type(exc).__name__}")
    text = "\n".join(item for item in texts if item)
    method = "hwp5-bodytext"
    if not text.strip() and ole.exists("PrvText"):
        text = ole.read("PrvText").decode("utf-16le", errors="ignore")
        method = "hwp5-prvtext"
        warnings.append("본문 대신 미리보기(PrvText) 텍스트 사용")
    if password or distribution:
        reason = "암호 설정 HWP 문서" if password else "배포용(DRM) HWP 문서: ViewText 암호화"
        return finalize(text, method=method, encrypted=True, empty_reason=reason, warnings=warnings)
    return finalize(text, method=method, warnings=warnings)


# --- HWPX ---------------------------------------------------------------------


def extract_hwpx_text(path: Path, *, max_member_bytes: int = 64 * 1024 * 1024) -> DocumentText:
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return DocumentText("", status="error", method="hwpx-zip", reason=f"ZIP 아님: {exc}")
    with archive:
        names = archive.namelist()
        if "META-INF/manifest.xml" in names:
            manifest = archive.read("META-INF/manifest.xml")
            if b"encryption-data" in manifest or b"encrypt" in manifest.lower():
                return finalize("", method="hwpx-zip", encrypted=True, empty_reason="암호화된 HWPX(manifest encryption-data)")
        sections = sorted(
            (name for name in names if re.match(r"(?i)^contents/section\d+\.xml$", name)),
            key=lambda name: int(re.sub(r"\D", "", name) or 0),
        )
        texts: list[str] = []
        warnings: list[str] = []
        for name in sections:
            info = archive.getinfo(name)
            if info.file_size > max_member_bytes:
                warnings.append(f"{name}: too large")
                continue
            try:
                root = safe_xml_fromstring(archive.read(name))
            except (ET.ParseError, ValueError) as exc:
                warnings.append(f"{name}: {type(exc).__name__}")
                continue
            for paragraph in root.iter():
                if not paragraph.tag.endswith("}p"):
                    continue
                runs = [node.text or "" for node in paragraph.iter() if node.tag.endswith("}t")]
                line = "".join(runs).strip()
                if line:
                    texts.append(line)
        if not sections and "Preview/PrvText.txt" in names:
            texts.append(archive.read("Preview/PrvText.txt").decode("utf-8", errors="ignore"))
            warnings.append("본문 대신 Preview/PrvText.txt 사용")
    return finalize("\n".join(texts), method="hwpx-section-xml", warnings=warnings)


# --- Word .doc (OLE2) -------------------------------------------------------------


def _word_piece_text(word: bytes, table: bytes, fc_clx: int, lcb_clx: int) -> str | None:
    clx = table[fc_clx : fc_clx + lcb_clx]
    position = 0
    while position < len(clx) and clx[position] == 0x01:  # Prc entries
        if position + 3 > len(clx):
            return None
        cb = struct.unpack_from("<H", clx, position + 1)[0]
        position += 3 + cb
    if position >= len(clx) or clx[position] != 0x02:
        return None
    lcb = struct.unpack_from("<I", clx, position + 1)[0]
    plc = clx[position + 5 : position + 5 + lcb]
    count = (len(plc) - 4) // 12
    if count <= 0:
        return None
    cps = struct.unpack_from(f"<{count + 1}I", plc, 0)
    pieces: list[str] = []
    for index in range(count):
        pcd_offset = (count + 1) * 4 + index * 8
        fc_raw = struct.unpack_from("<I", plc, pcd_offset + 2)[0]
        length = max(0, cps[index + 1] - cps[index])
        if fc_raw & 0x40000000:
            start = (fc_raw & 0x3FFFFFFF) // 2
            pieces.append(word[start : start + length].decode("cp1252", errors="replace"))
        else:
            start = fc_raw
            pieces.append(word[start : start + length * 2].decode("utf-16le", errors="replace"))
    return "".join(pieces)


_FIELD_INSTRUCTION_RE = re.compile("\x13[^\x13\x14\x15]*\x14?")


def _clean_word_text(text: str) -> str:
    text = _FIELD_INSTRUCTION_RE.sub("", text).replace("\x15", "")
    text = text.replace("\x07", "\t").replace("\x0b", "\n").replace("\x0c", "\n").replace("\r", "\n")
    return text


def _utf16_runs(data: bytes, *, min_chars: int = 4) -> list[str]:
    runs: list[str] = []
    for match in re.finditer(rb"(?:[\x20-\x7e\t\r\n]\x00|[\x00-\xff][\xac-\xd7]){%d,}" % min_chars, data):
        runs.append(match.group(0).decode("utf-16le", errors="ignore"))
    return runs


def extract_doc_text(path: Path) -> DocumentText:
    try:
        ole = open_ole(path)
    except OleError as exc:
        return DocumentText("", status="unsupported", method="doc-ole", reason=f"OLE2 문서 아님: {exc}")
    if not ole.exists("WordDocument"):
        return DocumentText("", status="unsupported", method="doc-ole", reason="WordDocument 스트림 없음")
    word = ole.read("WordDocument")
    if len(word) < 0x1AA or struct.unpack_from("<H", word, 0)[0] != 0xA5EC:
        return DocumentText("", status="unsupported", method="doc-ole", reason="Word FIB 시그니처 불일치")
    flags = struct.unpack_from("<H", word, 0x0A)[0]
    if flags & 0x0100:
        return finalize("", method="doc-fib", encrypted=True, empty_reason="암호 설정 Word 문서(fEncrypted)")
    table_name = "1Table" if flags & 0x0200 else "0Table"
    fc_clx, lcb_clx = struct.unpack_from("<II", word, 0x01A2)
    warnings: list[str] = []
    text: str | None = None
    if ole.exists(table_name) and lcb_clx:
        try:
            text = _word_piece_text(word, ole.read(table_name), fc_clx, lcb_clx)
        except (struct.error, OleError) as exc:
            warnings.append(f"piece table: {type(exc).__name__}")
    method = "doc-piece-table"
    if text is None:
        text = "\n".join(_utf16_runs(word[0x200:]))
        method = "doc-text-runs"
        warnings.append("piece table 해석 실패: UTF-16 텍스트 런으로 대체")
    return finalize(_clean_word_text(text), method=method, warnings=warnings)


# --- Excel .xls (BIFF8) -----------------------------------------------------------------


def _iter_biff_records(data: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(data):
        record_type, length = struct.unpack_from("<HH", data, offset)
        yield record_type, data[offset + 4 : offset + 4 + length]
        offset += 4 + length


class _ContinuedReader:
    """Reads across a record and its CONTINUE records (BIFF8 string rules)."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.chunk = 0
        self.pos = 0

    def _ensure(self) -> bool:
        while self.chunk < len(self.chunks) and self.pos >= len(self.chunks[self.chunk]):
            self.chunk += 1
            self.pos = 0
        return self.chunk < len(self.chunks)

    def read(self, size: int) -> bytes:
        out = bytearray()
        while size > 0 and self._ensure():
            current = self.chunks[self.chunk]
            take = min(size, len(current) - self.pos)
            out += current[self.pos : self.pos + take]
            self.pos += take
            size -= take
        return bytes(out)

    def read_chars(self, count: int, high_byte: bool) -> str:
        parts: list[str] = []
        while count > 0 and self.chunk < len(self.chunks):
            current = self.chunks[self.chunk]
            width = 2 if high_byte else 1
            available = (len(current) - self.pos) // width
            if available <= 0:
                # Character data continued in a CONTINUE record restarts with
                # a fresh option byte (fHighByte may change mid-string).
                self.chunk += 1
                self.pos = 0
                if self.chunk >= len(self.chunks) or not self.chunks[self.chunk]:
                    break
                high_byte = bool(self.chunks[self.chunk][0] & 0x01)
                self.pos = 1
                continue
            take = min(count, available)
            raw = current[self.pos : self.pos + take * width]
            parts.append(raw.decode("utf-16le" if high_byte else "latin-1", errors="replace"))
            self.pos += take * width
            count -= take
        return "".join(parts)

    def unicode_string(self) -> str:
        header = self.read(3)
        if len(header) < 3:
            return ""
        cch, option = struct.unpack("<HB", header)
        runs = struct.unpack("<H", self.read(2))[0] if option & 0x08 else 0
        ext = struct.unpack("<I", self.read(4))[0] if option & 0x04 else 0
        text = self.read_chars(cch, bool(option & 0x01))
        self.read(4 * runs + ext)
        return text


def extract_xls_text(path: Path) -> DocumentText:
    try:
        ole = open_ole(path)
    except OleError as exc:
        return DocumentText("", status="unsupported", method="xls-biff8", reason=f"OLE2 문서 아님: {exc}")
    stream_name = "Workbook" if ole.exists("Workbook") else ("Book" if ole.exists("Book") else "")
    if not stream_name:
        return DocumentText("", status="unsupported", method="xls-biff8", reason="Workbook 스트림 없음")
    data = ole.read(stream_name)
    records = list(_iter_biff_records(data))
    texts: list[str] = []
    sheet_names: list[str] = []
    warnings: list[str] = []
    index = 0
    while index < len(records):
        record_type, payload = records[index]
        if record_type == 0x002F:  # FILEPASS
            return finalize("\n".join(sheet_names), method="xls-biff8", encrypted=True, empty_reason="암호 설정 Excel 문서(FILEPASS)")
        if record_type == 0x0085 and len(payload) > 8:  # BOUNDSHEET8
            cch, option = payload[6], payload[7]
            sheet_names.append(payload[8 : 8 + cch * (2 if option & 1 else 1)].decode("utf-16le" if option & 1 else "latin-1", errors="replace"))
        elif record_type == 0x00FC:  # SST (+ CONTINUE)
            chunks = [payload[8:]]
            total_unique = struct.unpack_from("<I", payload, 4)[0] if len(payload) >= 8 else 0
            while index + 1 < len(records) and records[index + 1][0] == 0x003C:
                index += 1
                chunks.append(records[index][1])
            reader = _ContinuedReader(chunks)
            for _ in range(total_unique):
                if not reader._ensure():
                    break
                try:
                    value = reader.unicode_string()
                except struct.error:
                    warnings.append("SST truncated")
                    break
                if value.strip():
                    texts.append(value)
        elif record_type == 0x0204 and len(payload) > 8:  # LABEL
            cch = struct.unpack_from("<H", payload, 6)[0]
            option = payload[8]
            value = payload[9 : 9 + cch * (2 if option & 1 else 1)].decode("utf-16le" if option & 1 else "latin-1", errors="replace")
            if value.strip():
                texts.append(value)
        index += 1
    body = "\n".join([*(f"[{name}]" for name in sheet_names), *texts])
    return finalize(body, method="xls-biff8", warnings=warnings, empty_reason="문자열 셀 없음(숫자만 있거나 빈 통합 문서)")


# --- PowerPoint .ppt -------------------------------------------------------------------


def extract_ppt_text(path: Path) -> DocumentText:
    try:
        ole = open_ole(path)
    except OleError as exc:
        return DocumentText("", status="unsupported", method="ppt-records", reason=f"OLE2 문서 아님: {exc}")
    if not ole.exists("PowerPoint Document"):
        return DocumentText("", status="unsupported", method="ppt-records", reason="PowerPoint Document 스트림 없음")
    if ole.exists("EncryptedSummary"):
        return finalize("", method="ppt-records", encrypted=True, empty_reason="암호 설정 PowerPoint 문서")
    data = ole.read("PowerPoint Document")
    texts: list[str] = []
    offset = 0
    encrypted = False
    while offset + 8 <= len(data):
        ver_inst, record_type, length = struct.unpack_from("<HHI", data, offset)
        if (ver_inst & 0x0F) == 0x0F:  # container: descend
            offset += 8
            continue
        payload = data[offset + 8 : offset + 8 + length]
        if record_type == 0x0FA0:  # TextCharsAtom
            texts.append(payload.decode("utf-16le", errors="replace"))
        elif record_type == 0x0FA8:  # TextBytesAtom
            texts.append(payload.decode("latin-1", errors="replace"))
        elif record_type == 0x2F14:  # CryptSession10Container
            encrypted = True
        offset += 8 + length
    return finalize("\n".join(texts), method="ppt-records", encrypted=encrypted)


# --- PDF --------------------------------------------------------------------------------

_PDF_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.DOTALL)
_PDF_REF_RE = re.compile(rb"(\d+)\s+(\d+)\s+R\b")
_PDF_STREAM_SPLIT_RE = re.compile(rb"\bstream\r?\n", re.DOTALL)
_PDF_ENDSTREAM_RE = re.compile(rb"\r?\n?endstream\s*$", re.DOTALL)


@dataclass
class _PdfObject:
    dictionary: bytes
    stream: bytes | None


def _pdf_dict_value(dictionary: bytes, key: bytes) -> bytes | None:
    match = re.search(rb"/" + re.escape(key) + rb"(?![A-Za-z0-9])\s*", dictionary)
    if not match:
        return None
    rest = dictionary[match.end() :]
    if rest.startswith(b"<<"):
        depth = 0
        index = 0
        while index < len(rest) - 1:
            pair = rest[index : index + 2]
            if pair == b"<<":
                depth += 1
                index += 2
                continue
            if pair == b">>":
                depth -= 1
                index += 2
                if depth == 0:
                    return rest[:index]
                continue
            index += 1
        return rest
    if rest.startswith(b"["):
        end = rest.find(b"]")
        return rest[: end + 1] if end >= 0 else rest
    ref = re.match(rb"(\d+)\s+(\d+)\s+R", rest)
    if ref:
        return ref.group(0)
    token = re.match(rb"(/[^\s/<>\[\]()]+|[^\s/<>\[\]()]+)", rest)
    return token.group(0) if token else None


def _pdf_ref(value: bytes | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(rb"\s*(\d+)\s+\d+\s+R\s*", value)
    return int(match.group(1)) if match else None


class _PdfDocument:
    def __init__(self, data: bytes, *, max_stream_bytes: int = MAX_DECOMPRESSED_STREAM_BYTES) -> None:
        self.data = data
        self.max_stream_bytes = max_stream_bytes
        self.objects: dict[int, _PdfObject] = {}
        self.warnings: list[str] = []
        for match in _PDF_OBJ_RE.finditer(data):
            number = int(match.group(1))
            body = match.group(3)
            parts = _PDF_STREAM_SPLIT_RE.split(body, maxsplit=1)
            if len(parts) == 2:
                dictionary, stream = parts[0], _PDF_ENDSTREAM_RE.sub(b"", parts[1])
                self.objects[number] = _PdfObject(dictionary, stream)
            else:
                self.objects[number] = _PdfObject(body, None)
        self._expand_object_streams()

    def _expand_object_streams(self) -> None:
        for obj in list(self.objects.values()):
            if obj.stream is None or not re.search(rb"/Type\s*/ObjStm", obj.dictionary):
                continue
            content = self.stream_bytes(obj)
            if content is None:
                continue
            count = int((_pdf_dict_value(obj.dictionary, b"N") or b"0").strip() or 0)
            first = int((_pdf_dict_value(obj.dictionary, b"First") or b"0").strip() or 0)
            header = content[:first].split()
            pairs = [(int(header[i]), int(header[i + 1])) for i in range(0, min(len(header) - 1, count * 2), 2)]
            for position, (number, offset) in enumerate(pairs):
                end = pairs[position + 1][1] if position + 1 < len(pairs) else len(content) - first
                body = content[first + offset : first + end]
                self.objects.setdefault(number, _PdfObject(body, None))

    def get(self, ref: int | None) -> _PdfObject | None:
        return self.objects.get(ref) if ref is not None else None

    def resolve_dict(self, value: bytes | None) -> bytes:
        ref = _pdf_ref(value)
        if ref is not None:
            obj = self.get(ref)
            return obj.dictionary if obj else b""
        return value or b""

    def stream_bytes(self, obj: _PdfObject) -> bytes | None:
        if obj.stream is None:
            return None
        filters = _pdf_dict_value(obj.dictionary, b"Filter") or b""
        names = re.findall(rb"/([A-Za-z0-9]+)", filters)
        data = obj.stream
        for name in names:
            if name in (b"FlateDecode", b"Fl"):
                try:
                    data = _inflate(data, raw=False, limit=self.max_stream_bytes, label="pdf stream")
                except zlib.error:
                    try:
                        data = _inflate(data.lstrip(b"\r\n"), raw=False, limit=self.max_stream_bytes, label="pdf stream")
                    except zlib.error:
                        self.warnings.append("FlateDecode 실패")
                        return None
            else:
                return None  # DCT/JPX/CCITT/LZW: not a text stream
        return data

    def encrypted(self) -> bool:
        return bool(re.search(rb"/Encrypt\s+(\d+\s+\d+\s+R|<<)", self.data))

    def pages(self) -> list[_PdfObject]:
        return [obj for obj in self.objects.values() if re.search(rb"/Type\s*/Page(?![A-Za-z])", obj.dictionary)]

    def page_resources(self, page: _PdfObject) -> bytes:
        current: _PdfObject | None = page
        depth = 0
        while current is not None and depth < 32:
            value = _pdf_dict_value(current.dictionary, b"Resources")
            if value:
                return self.resolve_dict(value)
            current = self.get(_pdf_ref(_pdf_dict_value(current.dictionary, b"Parent")))
            depth += 1
        return b""


class _PdfFont:
    def __init__(self, doc: _PdfDocument, dictionary: bytes) -> None:
        self.code_bytes = 1
        self.cmap: dict[int, str] = {}
        encoding = _pdf_dict_value(dictionary, b"Encoding") or b""
        subtype = _pdf_dict_value(dictionary, b"Subtype") or b""
        self.composite = subtype.strip() == b"/Type0"
        self.identity = b"Identity" in encoding or self.composite
        if self.identity:
            self.code_bytes = 2
        self.codec = "cp1252"
        if b"MacRoman" in encoding:
            self.codec = "mac_roman"
        to_unicode = doc.get(_pdf_ref(_pdf_dict_value(dictionary, b"ToUnicode")))
        if to_unicode is not None:
            content = doc.stream_bytes(to_unicode)
            if content:
                self._parse_cmap(content)
        if not self.identity:
            # Simple fonts are single-byte by definition, whatever codespace
            # range the ToUnicode CMap declares (writers often say <0000>-<FFFF>).
            self.code_bytes = 1

    def _parse_cmap(self, content: bytes) -> None:
        spaces = re.findall(rb"begincodespacerange(.*?)endcodespacerange", content, re.DOTALL)
        for block in spaces:
            first = re.search(rb"<([0-9A-Fa-f]+)>", block)
            if first:
                self.code_bytes = max(1, len(first.group(1)) // 2)
                break
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", content, re.DOTALL):
            for source, target in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", block):
                self.cmap[int(source, 16)] = _utf16be_hex(target)
        for block in re.findall(rb"beginbfrange(.*?)endbfrange", content, re.DOTALL):
            for match in re.finditer(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])", block):
                low, high = int(match.group(1), 16), int(match.group(2), 16)
                target = match.group(3)
                if high - low > 65535:
                    continue
                if target.startswith(b"["):
                    items = re.findall(rb"<([0-9A-Fa-f]*)>", target)
                    for offset, item in enumerate(items[: high - low + 1]):
                        self.cmap[low + offset] = _utf16be_hex(item)
                else:
                    base_hex = target[1:-1]
                    if not base_hex:
                        continue
                    base = int(base_hex, 16)
                    width = len(base_hex)
                    for offset in range(high - low + 1):
                        self.cmap[low + offset] = _utf16be_hex(format(base + offset, f"0{width}x").encode())

    def decode(self, raw: bytes) -> str:
        if self.cmap:
            out: list[str] = []
            step = self.code_bytes
            for index in range(0, len(raw) - step + 1, step):
                code = int.from_bytes(raw[index : index + step], "big")
                out.append(self.cmap.get(code, ""))
            return "".join(out)
        if self.identity:
            return ""  # CID font without ToUnicode: glyph ids are not text
        return raw.decode(self.codec, errors="replace")


class _UnknownFont:
    """Font resource not found: glyph codes cannot be mapped to text."""

    def decode(self, raw: bytes) -> str:
        return ""


_UNKNOWN_FONT = _UnknownFont()


def _utf16be_hex(value: bytes) -> str:
    try:
        raw = bytes.fromhex(value.decode("ascii"))
    except ValueError:
        return ""
    if len(raw) % 2:
        raw = b"\x00" + raw
    return raw.decode("utf-16-be", errors="ignore")


_PDF_TOKEN_RE = re.compile(
    rb"\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)|<[0-9A-Fa-f\s]*>|\[|\]|/[^\s/<>\[\]()%]+|[-+]?\d*\.?\d+|[A-Za-z'\"*]+|%[^\r\n]*",
    re.DOTALL,
)
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}


def _pdf_literal_bytes(token: bytes) -> bytes:
    body = token[1:-1]
    out = bytearray()
    index = 0
    while index < len(body):
        char = body[index : index + 1]
        if char != b"\\":
            out += char
            index += 1
            continue
        nxt = body[index + 1 : index + 2]
        if nxt in _PDF_ESCAPES:
            out += _PDF_ESCAPES[nxt]
            index += 2
        elif nxt.isdigit():
            octal = re.match(rb"[0-7]{1,3}", body[index + 1 : index + 4])
            if octal:
                out.append(int(octal.group(0), 8) & 0xFF)
                index += 1 + len(octal.group(0))
            else:
                index += 2
        elif nxt in (b"\r", b"\n"):
            index += 2
        else:
            out += nxt
            index += 2
    return bytes(out)


def _pdf_string_bytes(token: bytes) -> bytes:
    if token.startswith(b"("):
        return _pdf_literal_bytes(token)
    hex_text = re.sub(rb"\s+", b"", token[1:-1])
    if len(hex_text) % 2:
        hex_text += b"0"
    try:
        return bytes.fromhex(hex_text.decode("ascii"))
    except ValueError:
        return b""


class _TextLayout:
    """Places decoded strings using the text position (BT/Td/TD/Tm/T*).

    A line break is emitted when the baseline moves, a space when the next
    string starts clearly after the estimated end of the previous one --
    writers that position every glyph separately (BT ... Td <glyph> Tj ET)
    then still produce words instead of one glyph per line.
    """

    def __init__(self) -> None:
        self.out: list[str] = []
        self.line_x = 0.0
        self.line_y = 0.0
        self.scale = 1.0
        self.font_size = 1.0
        self.last_y: float | None = None
        self.last_end_x: float | None = None

    @property
    def size(self) -> float:
        return max(0.1, abs(self.font_size * self.scale))

    def begin_text(self) -> None:
        self.line_x = self.line_y = 0.0
        self.scale = 1.0

    def move(self, tx: float, ty: float) -> None:
        self.line_x += tx * self.scale
        self.line_y += ty * self.scale

    def set_matrix(self, a: float, e: float, f: float) -> None:
        self.scale = abs(a) or 1.0
        self.line_x, self.line_y = e, f

    def newline(self) -> None:
        self.out.append("\n")
        self.last_y = None
        self.last_end_x = None

    def show(self, text: str) -> None:
        if not text:
            return
        if self.last_y is not None:
            if abs(self.line_y - self.last_y) > max(1.0, self.size * 0.5):
                self.out.append("\n")
            elif self.last_end_x is not None and self.line_x - self.last_end_x > self.size * 0.6:
                self.out.append(" ")
        self.out.append(text)
        self.last_y = self.line_y
        self.last_end_x = self.line_x + len(text) * self.size * 0.5
        self.line_x = self.last_end_x


def _pdf_number(token: bytes) -> float | None:
    try:
        return float(token)
    except ValueError:
        return None


def _pdf_content_text(content: bytes, fonts: Mapping[bytes, _PdfFont], default_font: _PdfFont) -> str:
    layout = _TextLayout()
    font: object = default_font
    operands: list[bytes] = []
    for match in _PDF_TOKEN_RE.finditer(content):
        token = match.group(0)
        first = token[:1]
        if first == b"%":
            continue
        if first in (b"(", b"<", b"[", b"]", b"/") or first.isdigit() or first in (b"-", b"+", b"."):
            operands.append(token)
            continue
        operator = token
        numbers = [_pdf_number(item) for item in operands]
        if operator == b"BT":
            layout.begin_text()
        elif operator == b"Tf" and len(operands) >= 2:
            # A resource-less page (minimal writers) uses a simple font; an
            # unknown name among known fonts is undecodable (likely CID).
            font = fonts.get(operands[-2].lstrip(b"/")) or (_UNKNOWN_FONT if fonts else default_font)
            layout.font_size = numbers[-1] or 1.0
        elif operator in (b"Td", b"TD") and len(numbers) >= 2 and None not in numbers[-2:]:
            layout.move(float(numbers[-2]), float(numbers[-1]))  # type: ignore[arg-type]
        elif operator == b"Tm" and len(numbers) >= 6 and None not in numbers[-6:]:
            layout.set_matrix(float(numbers[-6]), float(numbers[-2]), float(numbers[-1]))  # type: ignore[arg-type]
        elif operator == b"T*":
            layout.newline()
        elif operator in (b"Tj", b"'", b'"'):
            if operator != b"Tj":
                layout.newline()
            strings = [item for item in operands if item[:1] in (b"(", b"<")]
            if strings:
                layout.show(font.decode(_pdf_string_bytes(strings[-1])))  # type: ignore[attr-defined]
        elif operator == b"TJ":
            parts: list[str] = []
            for item in operands:
                if item[:1] in (b"(", b"<"):
                    parts.append(font.decode(_pdf_string_bytes(item)))  # type: ignore[attr-defined]
                else:
                    value = _pdf_number(item)
                    if value is not None and value < -200:
                        parts.append(" ")
            layout.show("".join(parts))
        operands = []
    return "".join(layout.out)


def _pdf_font_map(doc: _PdfDocument, resources: bytes) -> dict[bytes, _PdfFont]:
    fonts: dict[bytes, _PdfFont] = {}
    font_dict = doc.resolve_dict(_pdf_dict_value(resources, b"Font"))
    for name, number in re.findall(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R", font_dict):
        obj = doc.get(int(number))
        if obj is not None:
            fonts[name] = _PdfFont(doc, obj.dictionary)
    return fonts


def _pdf_global_font_map(doc: _PdfDocument) -> dict[bytes, _PdfFont]:
    """Fonts of every resource dictionary (fallback for inherited/Form resources)."""
    fonts: dict[bytes, _PdfFont] = {}
    for obj in doc.objects.values():
        if b"/Font" not in obj.dictionary:
            continue
        value = _pdf_dict_value(obj.dictionary, b"Font")
        if not value or not (value.startswith(b"<<") or _pdf_ref(value) is not None):
            continue
        for name, font in _pdf_font_map(doc, obj.dictionary).items():
            fonts.setdefault(name, font)
    return fonts


_PDF_NAMED_REF_RE = re.compile(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R")


def _pdf_form_texts(
    doc: _PdfDocument,
    resources: bytes,
    fonts: Mapping[bytes, _PdfFont],
    default_font: _PdfFont,
    *,
    depth: int,
) -> list[str]:
    """Text of Form XObjects drawn by a page, with their own font resources."""
    if depth > 4:
        return []
    texts: list[str] = []
    xobjects = doc.resolve_dict(_pdf_dict_value(resources, b"XObject"))
    for _name, number in _PDF_NAMED_REF_RE.findall(xobjects):
        obj = doc.get(int(number))
        if obj is None or not re.search(rb"/Subtype\s*/Form", obj.dictionary):
            continue
        form_resources = doc.resolve_dict(_pdf_dict_value(obj.dictionary, b"Resources"))
        form_fonts = {**fonts, **_pdf_font_map(doc, form_resources)}
        content = doc.stream_bytes(obj)
        if content and b"BT" in content:
            texts.append(_pdf_content_text(content, form_fonts, default_font))
        if form_resources:
            texts.extend(_pdf_form_texts(doc, form_resources, form_fonts, default_font, depth=depth + 1))
    return texts


def extract_pdf_document_text(path: Path, *, max_stream_bytes: int = MAX_DECOMPRESSED_STREAM_BYTES) -> DocumentText:
    data = path.read_bytes()
    if not data.lstrip()[:5].startswith(b"%PDF"):
        return DocumentText("", status="unsupported", method="pdf-native", reason="PDF 헤더 없음")
    doc = _PdfDocument(data, max_stream_bytes=max_stream_bytes)
    if doc.encrypted():
        return finalize("", method="pdf-native", encrypted=True, empty_reason="암호화된 PDF(/Encrypt): 본문 복호화 미지원")
    default_font = _PdfFont(doc, b"")
    global_fonts = _pdf_global_font_map(doc)
    texts: list[str] = []
    pages = doc.pages()
    image_only_pages = 0
    for page in pages:
        resources = doc.page_resources(page)
        fonts = {**global_fonts, **_pdf_font_map(doc, resources)}
        contents = _pdf_dict_value(page.dictionary, b"Contents") or b""
        refs = [int(number) for number, _gen in _PDF_REF_RE.findall(contents)]
        page_text: list[str] = []
        for ref in refs:
            obj = doc.get(ref)
            if obj is None:
                continue
            content = doc.stream_bytes(obj)
            if content and b"BT" in content:
                page_text.append(_pdf_content_text(content, fonts, default_font))
        page_text.extend(_pdf_form_texts(doc, resources, fonts, default_font, depth=0))
        text = "".join(page_text)
        if not text.strip() and b"/XObject" in resources:
            image_only_pages += 1
        texts.append(text)
    if not pages:
        # Malformed/linearized-only PDFs: scan every non-image stream with text objects.
        for obj in doc.objects.values():
            if obj.stream is None or re.search(rb"/Subtype\s*/Image|/Length1|/FontFile|/Type\s*/(XRef|ObjStm|Metadata)", obj.dictionary):
                continue
            content = doc.stream_bytes(obj)
            if content and b"BT" in content:
                texts.append(_pdf_content_text(content, _pdf_font_map(doc, b""), default_font))
    body = "\n".join(item for item in texts if item)
    reason = ""
    if not clean_extracted_text(body):
        reason = (
            f"텍스트 레이어 없음(이미지 전용 페이지 {image_only_pages}/{len(pages)}): OCR 필요"
            if image_only_pages
            else "텍스트 객체 없음 또는 ToUnicode 없는 CID 글꼴"
        )
    return finalize(body, method="pdf-native", empty_reason=reason, warnings=doc.warnings[:5])
