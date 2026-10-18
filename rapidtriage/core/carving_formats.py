"""Structural validators and boundary walkers for the R3 carving signatures (plan r3-os-depth §3.3).

Each format has a *validator* (header probe -> rejection reason or ``None``)
and, where the format states its own length, a *walker* (the bounded carve
window -> ``(length, status, boundary method)`` or a rejection reason):

* wav -- RIFF/WAVE + a plausible ``fmt `` chunk; RIFF size field;
* mp3 -- ID3v2 header (syncsafe size) or an MPEG-1/2/2.5 Layer III frame
  header; the walker follows consecutive frames (same version / layer /
  sample rate) and an ID3v1 ``TAG`` trailer;
* m4a / mp4 -- ISO BMFF ``ftyp`` box (major brand decides m4a vs mp4) and a
  top-level box walk that must see ``moov`` or ``mdat``;
* docx / xlsx / pptx / hwpx -- ZIP local headers: ``[Content_Types].xml``
  (inflated, main part content type) plus the app part (``word/``, ``xl/``,
  ``ppt/``), or ``mimetype`` = ``application/hwp+zip`` plus ``Contents/``;
  end of central directory whose central directory offset/size agree;
* hwp -- OLE compound file header, then FAT / directory / mini stream walk to
  the ``FileHeader`` stream that starts with ``HWP Document File``; length from
  the highest allocated FAT sector;
* eml -- a bounded RFC 5322 header block (field names, a blank line, From +
  Date/Message-ID + Subject/To); ends at the first NUL byte or the next
  message separator;
* pe -- MZ, ``PE\\0\\0`` at ``e_lfanew``, known machine, optional header magic,
  a section table with aligned raw pointers; length from sections and the
  certificate table;
* evtx -- ``ElfFile`` header (size 128, version 3, CRC32 of the first 120
  bytes) and the chunk count, chunks checked for ``ElfChnk``.

Rejection reasons starting with :data:`SILENT_PREFIXES` mean "not this format
at all" (a ZIP that is not Office, an OLE file that is not HWP, ``MZ`` without a
PE header): the scan drops them without a row, so ordinary data does not fill
the false-positive count. Every other reason is an auditable
``false-positive-rejected`` row.
"""

from __future__ import annotations

import re
import struct
import threading
import zlib

STATUS_LENGTH_FIELD = "length-field"
STATUS_LENGTH_FIELD_TRUNCATED = "length-field-truncated"
STATUS_FOOTER_VALIDATED = "footer-validated"
STATUS_BOUNDED_NO_FOOTER = "bounded-no-footer"
STATUS_TEXT_BOUNDARY = "text-boundary"

SILENT_PREFIXES: tuple[str, ...] = ("other-subtype:", "no-structure:")

Boundary = tuple[int, str, str]

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


def is_silent(reason: str | None) -> bool:
    return bool(reason) and str(reason).startswith(SILENT_PREFIXES)


def _length_boundary(declared: int, window: bytes, method: str) -> Boundary:
    if declared <= len(window):
        return declared, STATUS_LENGTH_FIELD, method
    return len(window), STATUS_LENGTH_FIELD_TRUNCATED, method


# --- wav ------------------------------------------------------------------------------

WAV_FORMATS = frozenset({0x0001, 0x0002, 0x0003, 0x0006, 0x0007, 0x0011, 0x0031, 0x0050, 0x0055, 0x0092, 0x0161, 0xFFFE})


def validate_wav(probe: bytes) -> str | None:
    if len(probe) < 12:
        return "truncated-riff-header"
    if probe[8:12] != b"WAVE":
        return "other-subtype:riff"
    position = 12
    while position + 8 <= len(probe):
        chunk_id = probe[position : position + 4]
        chunk_size = int.from_bytes(probe[position + 4 : position + 8], "little")
        if chunk_id == b"fmt ":
            if chunk_size < 16 or position + 24 > len(probe):
                return "wav-truncated-fmt-chunk"
            audio_format, channels, sample_rate, byte_rate, block_align, bits = struct.unpack_from(
                "<HHIIHH", probe, position + 8
            )
            if audio_format not in WAV_FORMATS:
                return f"wav-unknown-format:0x{audio_format:04x}"
            if not 1 <= channels <= 32 or not 1000 <= sample_rate <= 768_000 or block_align == 0:
                return "wav-implausible-fmt"
            if audio_format == 1 and (block_align != channels * ((bits + 7) // 8) or byte_rate != sample_rate * block_align):
                return "wav-inconsistent-pcm-fmt"
            return None
        if not chunk_id.isascii() or chunk_size > 64 * MIB:
            break
        position += 8 + chunk_size + (chunk_size & 1)
    return "wav-missing-fmt-chunk"


def walk_wav(window: bytes) -> Boundary | str:
    return _length_boundary(8 + int.from_bytes(window[4:8], "little"), window, "riff-size")


# --- mp3 ------------------------------------------------------------------------------

_MP3_BITRATES = {
    3: (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),  # MPEG-1
    2: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),  # MPEG-2
    0: (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),  # MPEG-2.5
}
_MP3_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}
MP3_MIN_FRAMES_ID3 = 2
MP3_MIN_FRAMES_SYNC = 8
# Fewer consecutive frames than this after a bare frame sync is ordinary data (no row at all).
MP3_SILENT_BELOW_FRAMES = 4
MP3_FIRST_FRAME_SEARCH = 4096


def mp3_frame(header: bytes) -> tuple[int, tuple[int, int, int]] | None:
    """``(frame length, (version, layer, rate index))`` of a Layer III frame header, else ``None``."""
    if len(header) < 4 or header[0] != 0xFF or header[1] & 0xE0 != 0xE0:
        return None
    version = (header[1] >> 3) & 0x03
    layer = (header[1] >> 1) & 0x03
    if version == 1 or layer != 1:  # reserved version / not Layer III
        return None
    bitrate_index = header[2] >> 4
    rate_index = (header[2] >> 2) & 0x03
    if bitrate_index in (0, 15) or rate_index == 3 or header[3] & 0x03 == 2:  # free/bad bitrate, reserved rate/emphasis
        return None
    bitrate = _MP3_BITRATES[version][bitrate_index] * 1000
    rate = _MP3_RATES[version][rate_index]
    padding = (header[2] >> 1) & 0x01
    factor = 144 if version == 3 else 72
    return factor * bitrate // rate + padding, (version, layer, rate_index)


def _walk_frames(window: bytes, start: int) -> tuple[int, int, bool]:
    """``(frames, end, reached window end)`` of consecutive frames from ``start``."""
    frames = 0
    position = start
    shape = None
    while position + 4 <= len(window):
        frame = mp3_frame(window[position : position + 4])
        if frame is None or (shape is not None and frame[1] != shape):
            return frames, position, False
        shape = frame[1]
        if position + frame[0] > len(window):
            return frames, position, True
        frames += 1
        position += frame[0]
    return frames, position, position >= len(window)


def _id3_size(probe: bytes) -> int | None:
    if len(probe) < 10 or probe[3] not in (2, 3, 4) or probe[4] == 0xFF:
        return None
    if any(byte & 0x80 for byte in probe[6:10]):
        return None
    size = (probe[6] << 21) | (probe[7] << 14) | (probe[8] << 7) | probe[9]
    footer = 10 if probe[3] == 4 and probe[5] & 0x10 else 0
    return 10 + size + footer


def validate_mp3_id3(probe: bytes) -> str | None:
    if len(probe) < 10:
        return "truncated-id3-header"
    if probe[3] not in (2, 3, 4) or probe[4] == 0xFF:
        return "no-structure:id3-invalid-version"
    if _id3_size(probe) is None:
        return "id3-invalid-syncsafe-size"
    if probe[5] & 0x0F:
        return "id3-invalid-flags"
    return None


def walk_mp3_id3(window: bytes) -> Boundary | str:
    tag_end = _id3_size(window) or 10
    if tag_end >= len(window):
        return len(window), STATUS_LENGTH_FIELD_TRUNCATED, "id3-size"
    # Frames follow the tag; tolerate padding before the first sync.
    first = -1
    for position in range(tag_end, min(len(window) - 4, tag_end + MP3_FIRST_FRAME_SEARCH) + 1):
        if window[position] == 0xFF and mp3_frame(window[position : position + 4]) is not None:
            first = position
            break
    if first < 0:
        return "mp3-no-frame-after-id3"
    frames, end, at_window_end = _walk_frames(window, first)
    if frames < MP3_MIN_FRAMES_ID3:
        return f"mp3-frame-walk-too-short:{frames}" if not at_window_end else "mp3-truncated-after-id3"
    if window[end : end + 3] == b"TAG" and end + 128 <= len(window):
        end += 128
    return end, STATUS_LENGTH_FIELD_TRUNCATED if at_window_end else STATUS_LENGTH_FIELD, "frame-walk"


def validate_mp3_sync(probe: bytes) -> str | None:
    return None if mp3_frame(probe[:4]) is not None else "no-structure:invalid-mpeg-header"


def walk_mp3_sync(window: bytes) -> Boundary | str:
    frames, end, at_window_end = _walk_frames(window, 0)
    if frames < MP3_SILENT_BELOW_FRAMES:
        return f"no-structure:mpeg-frames:{frames}"
    if frames < MP3_MIN_FRAMES_SYNC and not at_window_end:
        return f"mp3-frame-walk-too-short:{frames}"
    if window[end : end + 3] == b"TAG" and end + 128 <= len(window):
        end += 128
    return end, STATUS_LENGTH_FIELD_TRUNCATED if at_window_end else STATUS_LENGTH_FIELD, "frame-walk"


# --- m4a / mp4 ------------------------------------------------------------------------

M4A_BRANDS = frozenset({b"M4A ", b"M4B ", b"M4P "})
NON_AV_BRANDS = frozenset({b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis", b"jp2 ", b"jpx ", b"crx "})
_BRAND = re.compile(rb"^[0-9A-Za-z ._-]{4}$")
MP4_TOP_LEVEL = frozenset(
    {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pdin", b"moof", b"mfra",
     b"styp", b"sidx", b"ssix", b"prft", b"emsg", b"udta", b"pnot", b"junk", b"beam", b"PICT"}
)


def mp4_brand(probe: bytes) -> tuple[str | None, str | None]:
    """``(subtype, rejection)``: subtype ``m4a`` / ``mp4`` from the ``ftyp`` box at offset 0."""
    if len(probe) < 16:
        return None, "truncated-ftyp-box"
    size = int.from_bytes(probe[0:4], "big")
    if size < 16 or size > 4096 or (size - 16) % 4:
        return None, f"implausible-ftyp-size:{size}"
    major = probe[8:12]
    if not _BRAND.match(major):
        return None, "invalid-ftyp-major-brand"
    if major in NON_AV_BRANDS:
        return None, f"other-subtype:{major.decode('ascii', 'replace').strip()}"
    compatible = [probe[position : position + 4] for position in range(16, min(size, len(probe)) - 3, 4)]
    if major in M4A_BRANDS or (major in (b"mp42", b"isom") and any(brand in M4A_BRANDS for brand in compatible)):
        return "m4a", None
    return "mp4", None


def validate_m4a(probe: bytes) -> str | None:
    subtype, rejection = mp4_brand(probe)
    if rejection:
        # The mp4 signature reports a malformed ftyp once; m4a stays silent.
        return rejection if is_silent(rejection) else f"no-structure:{rejection}"
    return None if subtype == "m4a" else f"other-subtype:{subtype}"


def validate_mp4(probe: bytes) -> str | None:
    subtype, rejection = mp4_brand(probe)
    if rejection:
        return rejection
    return None if subtype == "mp4" else f"other-subtype:{subtype}"


def walk_bmff(window: bytes) -> Boundary | str:
    position = 0
    seen: set[bytes] = set()
    while position + 8 <= len(window):
        size = int.from_bytes(window[position : position + 4], "big")
        box = window[position + 4 : position + 8]
        if box not in MP4_TOP_LEVEL:
            break
        header = 8
        if size == 1:
            if position + 16 > len(window):
                return len(window), STATUS_LENGTH_FIELD_TRUNCATED, "box-walk"
            size = int.from_bytes(window[position + 8 : position + 16], "big")
            header = 16
        elif size == 0:  # box runs to the end of the file
            seen.add(box)
            return len(window), STATUS_LENGTH_FIELD_TRUNCATED, "box-walk"
        if size < header:
            break
        seen.add(box)
        if position + size > len(window):
            return len(window), STATUS_LENGTH_FIELD_TRUNCATED, "box-walk"
        position += size
    if not seen & {b"moov", b"mdat"}:
        return "mp4-no-moov-or-mdat"
    return position, STATUS_LENGTH_FIELD, "box-walk"


# --- ZIP containers (docx / xlsx / pptx / hwpx) ---------------------------------------

OOXML_MAIN_TYPES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("docx", ("wordprocessingml.document.main", "ms-word.document.macroenabled.main", "wordprocessingml.template.main")),
    ("xlsx", ("spreadsheetml.sheet.main", "ms-excel.sheet.macroenabled.main", "spreadsheetml.template.main")),
    (
        "pptx",
        (
            "presentationml.presentation.main",
            "ms-powerpoint.presentation.macroenabled.main",
            "presentationml.slideshow.main",
            "presentationml.template.main",
        ),
    ),
)
OOXML_APP_PREFIX = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}
HWPX_MIMETYPE = b"application/hwp+zip"
ZIP_MEMBER_LIMIT = 256
ZIP_INFLATE_LIMIT = 256 * KIB
_local = threading.local()


def _inflate(data: bytes, method: int, size: int) -> bytes | None:
    if method == 0:
        return data[:size] if len(data) >= size else None
    if method != 8:
        return None
    try:
        return zlib.decompressobj(-15).decompress(data, ZIP_INFLATE_LIMIT)
    except zlib.error:
        return None


def zip_members(probe: bytes) -> tuple[list[str], dict[str, bytes | None], bool]:
    """Local-header walk: ``(member names, {interesting name: content}, walk complete)``."""
    names: list[str] = []
    contents: dict[str, bytes | None] = {}
    position = 0
    while position + 30 <= len(probe) and len(names) < ZIP_MEMBER_LIMIT:
        signature = probe[position : position + 4]
        if signature in (b"PK\x01\x02", b"PK\x05\x06"):
            return names, contents, True
        if signature != b"PK\x03\x04":
            break
        flags, method = struct.unpack_from("<HH", probe, position + 6)
        compressed, uncompressed, name_length, extra_length = struct.unpack_from("<IIHH", probe, position + 18)
        name_start = position + 30
        data_start = name_start + name_length + extra_length
        if data_start > len(probe):
            break
        name = probe[name_start : name_start + name_length].decode("utf-8" if flags & 0x800 else "cp437", "replace")
        names.append(name)
        if name in ("[Content_Types].xml", "mimetype"):
            available = probe[data_start : data_start + (compressed or ZIP_INFLATE_LIMIT)]
            contents[name] = _inflate(available, method, uncompressed)
        if flags & 0x08 and compressed == 0:
            # Sizes live in a data descriptor after the data: resync on the next header.
            following = [
                index
                for index in (probe.find(b"PK\x03\x04", data_start), probe.find(b"PK\x01\x02", data_start))
                if index >= 0
            ]
            if not following:
                break
            position = min(following)
            continue
        position = data_start + compressed
    return names, contents, False


def classify_zip(probe: bytes) -> tuple[str, str | None, str | None]:
    """``(subtype, rejection, reporter)`` of a ZIP at offset 0: ``zip`` / ``docx`` / ``xlsx`` / ``pptx`` / ``hwpx``.

    ``rejection`` (with the kind that reports it) when the container claims an
    Office/HWPX type but lacks its required part. One-entry per-thread cache:
    the four container signatures validate the same probe object in a row.
    """
    cached = getattr(_local, "zip", None)
    if cached is not None and cached[0] is probe:
        return cached[1]
    result = _classify_zip(probe)
    _local.zip = (probe, result)
    return result


def _classify_zip(probe: bytes) -> tuple[str, str | None, str | None]:
    names, contents, _complete = zip_members(probe)
    mimetype = contents.get("mimetype")
    has_contents = any(name.startswith("Contents/") for name in names)
    if mimetype is not None and mimetype.strip() == HWPX_MIMETYPE:
        return ("hwpx", None, None) if has_contents else ("hwpx", "hwpx-missing-contents-part", "hwpx")
    if "mimetype" in names and has_contents:
        return "hwpx", "hwpx-unreadable-mimetype", "hwpx"
    app_guess = next((kind for kind, prefix in OOXML_APP_PREFIX.items() if any(n.startswith(prefix) for n in names)), None)
    if "[Content_Types].xml" not in names:
        if app_guess and any(name.startswith("_rels/") for name in names):
            return app_guess, "ooxml-missing-content-types", app_guess
        return "zip", None, None
    content_types = contents.get("[Content_Types].xml")
    if content_types is None:
        return app_guess or "docx", "ooxml-content-types-unreadable", app_guess or "docx"
    lowered = content_types.decode("utf-8", "replace").lower()
    declared = next((kind for kind, markers in OOXML_MAIN_TYPES if any(marker in lowered for marker in markers)), None)
    if declared is None:
        return "zip", None, None  # another OPC package (xps, vsdx, nupkg ...)
    if not any(name.startswith(OOXML_APP_PREFIX[declared]) for name in names):
        return declared, f"ooxml-missing-app-part:{OOXML_APP_PREFIX[declared]}", declared
    return declared, None, None


def zip_container_validator(kind: str):
    def validate(probe: bytes) -> str | None:
        if len(probe) < 30:
            return "no-structure:truncated-zip-header"  # the generic zip signature reports it
        subtype, rejection, reporter = classify_zip(probe)
        if subtype == kind and rejection is None:
            return None
        if rejection is not None and reporter == kind:
            return rejection
        return f"other-subtype:{subtype}"

    validate.__name__ = f"validate_{kind}"
    return validate


def walk_zip(window: bytes) -> Boundary | str:
    """End of the archive: an EOCD whose central directory offset + size end right at it."""
    position = window.find(b"PK\x05\x06", 30)
    while 0 <= position and position + 22 <= len(window):
        cd_size, cd_offset, comment_length = struct.unpack_from("<IIH", window, position + 12)
        if cd_offset + cd_size == position and window[cd_offset : cd_offset + 4] == b"PK\x01\x02":
            end = position + 22 + comment_length
            if end <= len(window):
                return end, STATUS_FOOTER_VALIDATED, "zip-eocd"
            break
        position = window.find(b"PK\x05\x06", position + 4)
    return len(window), STATUS_BOUNDED_NO_FOOTER, "zip-eocd"


# --- hwp (OLE compound file) ----------------------------------------------------------

HWP_SIGNATURE = b"HWP Document File"
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
CFB_MAX_CHAIN = 1_000_000


def validate_cfb(probe: bytes) -> str | None:
    if len(probe) < 512:
        return "truncated-ole-header"
    major, byte_order, sector_shift, mini_shift = struct.unpack_from("<HHHH", probe, 0x1A)
    if byte_order != 0xFFFE:
        return "ole-invalid-byte-order"
    if (major, sector_shift) not in ((3, 9), (4, 12)) or mini_shift != 6:
        return "ole-invalid-sector-shift"
    return None


class _Cfb:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.fat = self._read_fat()

    def sector(self, number: int) -> bytes | None:
        start = (number + 1) * self.sector_size
        if start + self.sector_size > len(self.data):
            return None
        return self.data[start : start + self.sector_size]

    def _read_fat(self) -> list[int] | None:
        fat_count = struct.unpack_from("<I", self.data, 0x2C)[0]
        difat = [value for value in struct.unpack_from("<109I", self.data, 0x4C) if value != FREESECT]
        next_difat, difat_count = struct.unpack_from("<II", self.data, 0x44)
        steps = 0
        while next_difat not in (FREESECT, ENDOFCHAIN) and steps < min(difat_count, 4096):
            block = self.sector(next_difat)
            if block is None:
                return None
            values = struct.unpack(f"<{self.sector_size // 4}I", block)
            difat.extend(value for value in values[:-1] if value != FREESECT)
            next_difat = values[-1]
            steps += 1
        if fat_count == 0 or len(difat) < fat_count:
            return None
        fat: list[int] = []
        for number in difat[:fat_count]:
            block = self.sector(number)
            if block is None:
                return None
            fat.extend(struct.unpack(f"<{self.sector_size // 4}I", block))
        return fat

    def chain(self, start: int, fat: list[int]) -> list[int] | None:
        sectors: list[int] = []
        seen: set[int] = set()
        current = start
        while current not in (ENDOFCHAIN, FREESECT):
            if current in seen or current >= len(fat) or len(sectors) > CFB_MAX_CHAIN:
                return None
            seen.add(current)
            sectors.append(current)
            current = fat[current]
        return sectors

    def read(self, start: int, size: int | None = None) -> bytes | None:
        assert self.fat is not None
        sectors = self.chain(start, self.fat)
        if sectors is None:
            return None
        parts = []
        for number in sectors:
            block = self.sector(number)
            if block is None:
                return None
            parts.append(block)
        blob = b"".join(parts)
        return blob if size is None else blob[:size]


def walk_hwp(window: bytes) -> Boundary | str:
    if len(window) < 1024:
        return "hwp-truncated"
    cfb = _Cfb(window)
    if cfb.fat is None:
        return "hwp-fat-beyond-window"
    first_directory = struct.unpack_from("<I", window, 0x30)[0]
    directory = cfb.read(first_directory)
    if directory is None:
        return "hwp-directory-beyond-window"
    entries: dict[str, tuple[int, int, int]] = {}
    root: tuple[int, int] | None = None
    for position in range(0, len(directory) - 127, 128):
        entry = directory[position : position + 128]
        name_length = struct.unpack_from("<H", entry, 0x40)[0]
        kind = entry[0x42]
        if kind == 0 or not 2 <= name_length <= 64:
            continue
        name = entry[: name_length - 2].decode("utf-16le", "replace")
        start = struct.unpack_from("<I", entry, 0x74)[0]
        size = struct.unpack_from("<I", entry, 0x78)[0]
        if kind == 5 and root is None:
            root = (start, size)
        elif kind == 2:
            entries.setdefault(name, (start, size, kind))
    if "FileHeader" not in entries:
        return "other-subtype:ole"
    start, size, _kind = entries["FileHeader"]
    cutoff = struct.unpack_from("<I", window, 0x38)[0]
    if size < len(HWP_SIGNATURE):
        return "hwp-fileheader-too-small"
    if size < cutoff:
        minifat_start = struct.unpack_from("<I", window, 0x3C)[0]
        minifat_raw = cfb.read(minifat_start) if root is not None else None
        stream = cfb.read(root[0]) if root is not None else None
        if minifat_raw is None or stream is None:
            return "hwp-mini-stream-beyond-window"
        minifat = list(struct.unpack(f"<{len(minifat_raw) // 4}I", minifat_raw[: len(minifat_raw) // 4 * 4]))
        sectors = cfb.chain(start, minifat)
        if sectors is None:
            return "hwp-fileheader-chain-invalid"
        content = b"".join(stream[number * 64 : number * 64 + 64] for number in sectors)[:size]
    else:
        content = cfb.read(start, size) or b""
    if not content.startswith(HWP_SIGNATURE):
        return "other-subtype:ole"
    used = [index for index, value in enumerate(cfb.fat) if value != FREESECT]
    declared = (max(used) + 2) * cfb.sector_size if used else len(window)
    return _length_boundary(declared, window, "ole-fat")


# --- eml ------------------------------------------------------------------------------

_HEADER_NAME = re.compile(rb"^[!-9;-~]{1,76}:")
EML_HEADER_MAX = 64 * KIB
EML_MIN_FIELDS = 4
_EML_NEXT_MESSAGE = (b"\nFrom ", b"\nReturn-Path: ", b"\nDelivered-To: ")


def _eml_header_names(probe: bytes) -> tuple[list[bytes], int] | str:
    names: list[bytes] = []
    position = 0
    while position < len(probe):
        newline = probe.find(b"\n", position)
        if newline < 0:
            return "eml-header-unterminated"
        line = probe[position:newline].rstrip(b"\r")
        position = newline + 1
        if not line:
            return names, position
        if line[:1] in (b" ", b"\t"):
            if not names:
                return "eml-invalid-header-line"
            continue
        match = _HEADER_NAME.match(line)
        if match is None or b"\x00" in line:
            return "eml-invalid-header-line"
        names.append(line[: match.end() - 1].lower())
    return "eml-header-unterminated"


def validate_eml(probe: bytes) -> str | None:
    parsed = _eml_header_names(probe[:EML_HEADER_MAX])
    if isinstance(parsed, str):
        return parsed
    names = set(parsed[0])
    if len(parsed[0]) < EML_MIN_FIELDS:
        return "eml-too-few-header-fields"
    if b"from" not in names or not names & {b"date", b"message-id"} or not names & {b"subject", b"to"}:
        return "eml-missing-required-fields"
    return None


def walk_eml(window: bytes) -> Boundary | str:
    parsed = _eml_header_names(window[:EML_HEADER_MAX])
    body_start = parsed[1] if not isinstance(parsed, str) else 0
    ends = [index for index in (window.find(b"\x00", body_start),) if index >= 0]
    for marker in _EML_NEXT_MESSAGE:
        index = window.find(marker, body_start)
        if index >= 0:
            ends.append(index + 1)
    if ends:
        return min(ends), STATUS_TEXT_BOUNDARY, "text-boundary"
    return len(window), STATUS_BOUNDED_NO_FOOTER, "text-boundary"


# --- pe -------------------------------------------------------------------------------

PE_MACHINES = frozenset({0x014C, 0x8664, 0x01C0, 0x01C4, 0xAA64, 0x0200, 0x0166, 0x01A2, 0x01F0, 0x5032, 0x5064, 0x0EBC})
PE_PROBE_BYTES = 4 * KIB


def _pe_layout(probe: bytes) -> dict[str, object] | str:
    if len(probe) < 0x40:
        return "truncated-mz-header"
    pe_offset = int.from_bytes(probe[0x3C:0x40], "little")
    if not 0x40 <= pe_offset <= len(probe) - 24:
        return "no-structure:pe-header-offset"
    if probe[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return "no-structure:missing-pe-signature"
    machine, sections, _stamp, _symbols, _count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", probe, pe_offset + 4
    )
    if machine not in PE_MACHINES:
        return f"pe-unknown-machine:0x{machine:04x}"
    if not 1 <= sections <= 96:
        return f"pe-implausible-section-count:{sections}"
    optional = pe_offset + 24
    if optional + 2 > len(probe):
        return "pe-truncated-optional-header"
    magic = int.from_bytes(probe[optional : optional + 2], "little")
    if magic not in (0x10B, 0x20B) or optional_size < (96 if magic == 0x10B else 112):
        return "pe-invalid-optional-header"
    if optional + 64 > len(probe):
        return "pe-truncated-optional-header"
    file_alignment, _image_version, _subsystem_version = struct.unpack_from("<IIQ", probe, optional + 36)
    size_of_headers = int.from_bytes(probe[optional + 60 : optional + 64], "little")
    if not (32 <= file_alignment <= 65536 and not file_alignment & (file_alignment - 1)):
        return f"pe-invalid-file-alignment:{file_alignment}"
    table = optional + optional_size
    if table + 40 * sections > len(probe):
        return "pe-section-table-beyond-probe"
    end = size_of_headers
    for index in range(sections):
        entry = probe[table + 40 * index : table + 40 * index + 40]
        name = entry[:8].rstrip(b"\x00")
        if any(byte < 0x20 or byte > 0x7E for byte in name):
            return "pe-invalid-section-name"
        raw_size, raw_pointer = struct.unpack_from("<II", entry, 16)
        if raw_size and raw_pointer % file_alignment and raw_pointer % 512:
            return "pe-unaligned-section"
        if raw_pointer + raw_size > 2 * GIB:
            return "pe-implausible-section-size"
        if raw_size:
            end = max(end, raw_pointer + raw_size)
    directory = optional + (96 if magic == 0x10B else 112)
    security = directory + 4 * 8
    if security + 8 <= table and security + 8 <= len(probe):
        cert_offset, cert_size = struct.unpack_from("<II", probe, security)
        if cert_offset and cert_size and cert_offset >= end and cert_offset + cert_size <= 2 * GIB:
            end = cert_offset + cert_size
    return {"end": end, "dll": bool(characteristics & 0x2000), "machine": machine}


def validate_pe(probe: bytes) -> str | None:
    layout = _pe_layout(probe)
    return layout if isinstance(layout, str) else None


def walk_pe(window: bytes) -> Boundary | str:
    layout = _pe_layout(window[:PE_PROBE_BYTES])
    if isinstance(layout, str):
        return layout
    return _length_boundary(int(layout["end"]), window, "section-table")  # type: ignore[arg-type]


# --- evtx -----------------------------------------------------------------------------

EVTX_HEADER_BLOCK = 4096
EVTX_CHUNK = 65536


def validate_evtx(probe: bytes) -> str | None:
    if len(probe) < 128:
        return "truncated-evtx-header"
    header_size, minor, major, block_size = struct.unpack_from("<IHHH", probe, 0x20)
    if header_size != 128 or major != 3 or block_size != EVTX_HEADER_BLOCK:
        return "evtx-invalid-header-fields"
    if minor not in (1, 2):
        return f"evtx-unknown-minor-version:{minor}"
    if zlib.crc32(probe[:120]) & 0xFFFFFFFF != int.from_bytes(probe[0x7C:0x80], "little"):
        return "evtx-header-checksum-mismatch"
    return None


def walk_evtx(window: bytes) -> Boundary | str:
    declared = int.from_bytes(window[0x2A:0x2C], "little")
    chunks = 0
    position = EVTX_HEADER_BLOCK
    while position + 8 <= len(window) and window[position : position + 8] == b"ElfChnk\x00":
        chunks += 1
        position += EVTX_CHUNK
    if declared and not chunks and len(window) > EVTX_HEADER_BLOCK + 8:
        return "evtx-no-valid-chunk"
    total = EVTX_HEADER_BLOCK + max(declared, chunks) * EVTX_CHUNK
    return _length_boundary(total, window, "chunk-count")
