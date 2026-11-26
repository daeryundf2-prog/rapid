"""Residue memory sources for the KakaoTalk memory analyses: hiberfil.sys, pagefile.sys, swapfile.sys.

The KakaoTalk memory analyses read whole process dumps. Residue sources are
often many gigabytes, so they are streamed as bounded segments: each segment
is written to a temporary file (at most ``segment_bytes``), the existing
per-source analysis runs on it, and every hit is mapped back to the original
file, byte offset and page number. Hits are marked as residue evidence with
``triage`` confidence, below a live process dump.

hiberfil.sys: Windows 8+ layout (``HIBR``/``WAKE`` header, boot and kernel
restoration sets of compression sets, plain Xpress or Xpress-Huffman),
offsets per build following the public LeechCore ``device_hibr.c`` profile
table. Page numbers are physical frame numbers from the set descriptors.
Pre-Windows 8 files, wiped headers and unknown header sizes are reported as
unsupported rather than guessed. pagefile.sys / swapfile.sys: raw 4 KiB page
scan; page number = file offset // 4096.

Any other source handed to ``iter_residue_segments`` is a process dump too
large to hold in memory (the main run's cap): it is read with the same raw
page reader, but its hits keep the process-memory evidence class.
"""

from __future__ import annotations

import struct
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..artifacts.windows import xpress_huffman, xpress_lz77

RESIDUE_SOURCE_KINDS = {
    "hiberfil.sys": "hiberfil",
    "pagefile.sys": "pagefile",
    "swapfile.sys": "swapfile",
}
RESIDUE_PAGE_SIZE = 4096
DEFAULT_RESIDUE_SEGMENT_BYTES = 64 * 1024 * 1024
RESIDUE_SEGMENT_OVERLAP_BYTES = 64 * 1024
RESIDUE_EVIDENCE_CLASS = "memory-residue"
RESIDUE_CONFIDENCE = "triage"
SEGMENTED_DUMP_KIND = "process-dump"
SEGMENTED_DUMP_EVIDENCE_CLASS = "process-memory"
SEGMENTED_DUMP_CONFIDENCE = "needs-validation"
RESIDUE_PROVENANCE_KEYS = (
    "source_kind",
    "page_number",
    "page_offset",
    "segment_offset",
    "evidence_class",
    "confidence",
)
HIBR_SIGNATURES = {b"HIBR": "HIBR", b"WAKE": "WAKE"}
HIBR_MAX_PAGES_PER_SET = 16
HIBR_MAX_COMPRESSED_BYTES = HIBR_MAX_PAGES_PER_SET * RESIDUE_PAGE_SIZE
# PO_MEMORY_IMAGE length -> (32-bit, PageSize, NumPagesForLoader, FirstBootRestorePage,
# FirstKernelRestorePage, KernelPagesProcessed); Windows 8 (9200) through 11 24H2 (26100).
HIBR_LAYOUTS: dict[int, tuple[bool, int, int, int, int, int]] = {
    0x4D8: (False, 0x18, 0x58, 0x68, 0x70, 0x238),
    0x448: (False, 0x18, 0x58, 0x68, 0x70, 0x230),
    0x3E0: (False, 0x18, 0x58, 0x68, 0x70, 0x230),
    0x3D8: (False, 0x18, 0x58, 0x68, 0x70, 0x230),
    0x3C8: (False, 0x18, 0x58, 0x68, 0x70, 0x220),
    0x3B0: (False, 0x18, 0x58, 0x68, 0x70, 0x218),
    0x360: (False, 0x18, 0x58, 0x60, 0x68, 0x1C8),
    0x340: (True, 0x14, 0x48, 0x50, 0x54, 0x210),
    0x338: (True, 0x14, 0x48, 0x50, 0x54, 0x210),
    0x328: (True, 0x14, 0x48, 0x50, 0x54, 0x200),
    0x310: (True, 0x14, 0x48, 0x50, 0x54, 0x1F8),
    0x2C8: (True, 0x14, 0x48, 0x50, 0x54, 0x1B0),
}


class ResidueFormatError(ValueError):
    """A residue source is corrupt or uses a layout this reader does not support."""


@dataclass
class ResidueSourceStatus:
    path: Path
    kind: str
    size: int
    status: str = "not-read"
    layout: str = ""
    pages_read: int = 0
    segments_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def evidence_class(self) -> str:
        return SEGMENTED_DUMP_EVIDENCE_CLASS if self.kind == SEGMENTED_DUMP_KIND else RESIDUE_EVIDENCE_CLASS

    @property
    def confidence(self) -> str:
        return SEGMENTED_DUMP_CONFIDENCE if self.kind == SEGMENTED_DUMP_KIND else RESIDUE_CONFIDENCE

    def to_dict(self) -> dict[str, object]:
        return {
            "source_path": str(self.path),
            "source_kind": self.kind,
            "size": self.size,
            "status": self.status,
            "layout": self.layout,
            "pages_read": self.pages_read,
            "segments_scanned": self.segments_scanned,
            "errors": list(self.errors),
            "evidence_class": self.evidence_class,
            "confidence": self.confidence,
        }


@dataclass
class ResidueSegment:
    """One bounded slice of a residue source, materialised at ``path`` while it is scanned."""

    path: Path
    source: ResidueSourceStatus
    # (segment offset, source file offset, page number) for each 4 KiB page, ascending.
    pages: list[tuple[int, int, int]]
    owned_start: int
    owned_end: int

    def locate(self, segment_offset: int) -> dict[str, object] | None:
        """Provenance for a hit at ``segment_offset``, or None when a neighbouring segment owns it."""
        if not self.owned_start <= segment_offset < self.owned_end:
            return None
        low, high = 0, len(self.pages) - 1
        while low < high:
            middle = (low + high + 1) // 2
            if self.pages[middle][0] <= segment_offset:
                low = middle
            else:
                high = middle - 1
        page_segment_offset, page_source_offset, page_number = self.pages[low]
        within_page = segment_offset - page_segment_offset
        compressed = self.source.kind == "hiberfil"
        return {
            "source_path": str(self.source.path),
            "source_kind": self.source.kind,
            # Hiberfil pages are decompressed: the file offset is that of the compression set.
            "source_offset": page_source_offset
            if compressed
            else page_source_offset + within_page,
            "page_number": page_number,
            "page_offset": within_page,
            "evidence_class": self.source.evidence_class,
            "confidence": self.source.confidence,
        }

    def remap(
        self, hit: Mapping[str, object], *, offset_key: str = "source_offset"
    ) -> dict[str, object] | None:
        segment_offset = hit.get(offset_key)
        provenance = (
            self.locate(segment_offset) if isinstance(segment_offset, int) else None
        )
        if provenance is None:
            return None
        remapped = dict(hit)
        remapped["segment_offset"] = hit.get(offset_key, 0)
        remapped.update(provenance)
        return remapped


def find_residue_memory_sources(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.name.lower() in RESIDUE_SOURCE_KINDS and path.is_file()
        ),
        key=lambda item: str(item).lower(),
    )


def iter_residue_segments(
    sources: list[Path],
    *,
    statuses: list[ResidueSourceStatus],
    segment_bytes: int = DEFAULT_RESIDUE_SEGMENT_BYTES,
) -> Iterator[ResidueSegment]:
    """Yield bounded segments of every source; one temporary segment file exists at a time.

    A status per source is appended to ``statuses`` (unsupported and corrupt
    files are reported there and never raise).
    """
    with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-residue-") as temp_dir:
        for index, source in enumerate(sources):
            kind = RESIDUE_SOURCE_KINDS.get(source.name.lower(), SEGMENTED_DUMP_KIND)
            status = ResidueSourceStatus(path=source.resolve(), kind=kind, size=0)
            statuses.append(status)
            try:
                status.size = source.stat().st_size
            except OSError as exc:
                status.errors.append(str(exc))
                status.status = "error"
                continue
            reader = (
                iter_hiberfil_segments if kind == "hiberfil" else iter_raw_page_segments
            )
            segment_path: Path | None = None
            try:
                for data, pages, owned_start, owned_end in reader(
                    source, status, segment_bytes
                ):
                    if segment_path is not None:
                        segment_path.unlink(missing_ok=True)
                    segment_path = (
                        Path(temp_dir)
                        / f"{source.stem}-{index:03d}-seg{status.segments_scanned:05d}.mem"
                    )
                    segment_path.write_bytes(data)
                    status.segments_scanned += 1
                    yield ResidueSegment(
                        segment_path, status, pages, owned_start, owned_end
                    )
            except (OSError, ResidueFormatError) as exc:
                status.errors.append(str(exc))
                status.status = "partial" if status.pages_read else "error"
            finally:
                if segment_path is not None:
                    segment_path.unlink(missing_ok=True)


def iter_raw_page_segments(
    source: Path, status: ResidueSourceStatus, segment_bytes: int
) -> Iterator[tuple[bytes, list[tuple[int, int, int]], int, int]]:
    status.layout = "raw-pages"
    overlap = min(RESIDUE_SEGMENT_OVERLAP_BYTES, segment_bytes // 2)
    step = segment_bytes - overlap
    with source.open("rb") as handle:
        start = 0
        while start < status.size:
            handle.seek(start)
            data = handle.read(segment_bytes)
            if not data:
                break
            last = start + len(data) >= status.size
            pages = [
                (offset, start + offset, (start + offset) // RESIDUE_PAGE_SIZE)
                for offset in range(0, len(data), RESIDUE_PAGE_SIZE)
            ]
            status.pages_read = (
                start + len(data) + RESIDUE_PAGE_SIZE - 1
            ) // RESIDUE_PAGE_SIZE
            status.status = "read"
            yield data, pages, 0, len(data) if last else step
            if last:
                break
            start += step
    status.status = "read"


@dataclass
class HiberfilHeader:
    layout: str
    is_32bit: bool
    restore_sets: list[tuple[int, int]]


def parse_hiberfil_header(header: bytes) -> HiberfilHeader:
    signature = header[:4]
    if signature not in HIBR_SIGNATURES:
        if signature == b"\x00\x00\x00\x00":
            raise ResidueFormatError(
                "unsupported hiberfil: header page is zeroed (typically wiped after resume)"
            )
        raise ResidueFormatError(
            f"unsupported hiberfil signature {signature!r} (Windows 8+ HIBR/WAKE expected)"
        )
    length_self = struct.unpack_from("<I", header, 0x0C)[0]
    layout = HIBR_LAYOUTS.get(length_self)
    if layout is None:
        raise ResidueFormatError(
            f"unsupported hiberfil layout: PO_MEMORY_IMAGE length 0x{length_self:x}"
        )
    is_32bit, page_size_at, loader_pages_at, boot_at, kernel_at, kernel_pages_at = (
        layout
    )
    page_size = struct.unpack_from("<I", header, page_size_at)[0]
    if page_size != RESIDUE_PAGE_SIZE:
        raise ResidueFormatError(f"unsupported hiberfil page size {page_size}")
    pointer = "<I" if is_32bit else "<Q"
    return HiberfilHeader(
        layout=f"{HIBR_SIGNATURES[signature]}-windows8+-{'x86' if is_32bit else 'x64'}-0x{length_self:x}",
        is_32bit=is_32bit,
        restore_sets=[
            (
                struct.unpack_from(pointer, header, boot_at)[0],
                struct.unpack_from("<Q", header, loader_pages_at)[0],
            ),
            (
                struct.unpack_from(pointer, header, kernel_at)[0],
                struct.unpack_from("<Q", header, kernel_pages_at)[0],
            ),
        ],
    )


def iter_hiberfil_pages(
    source: Path, status: ResidueSourceStatus
) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(physical page number, compression set file offset, page bytes)``."""
    with source.open("rb") as handle:
        header = handle.read(RESIDUE_PAGE_SIZE)
        if len(header) < RESIDUE_PAGE_SIZE:
            raise ResidueFormatError("hiberfil is shorter than one header page")
        parsed = parse_hiberfil_header(header)
        status.layout = parsed.layout
        status.status = "read"
        descriptor_size = 4 if parsed.is_32bit else 8
        for first_page, page_total in parsed.restore_sets:
            offset = first_page * RESIDUE_PAGE_SIZE
            remaining = page_total
            while remaining > 0:
                if offset + 4 > status.size:
                    raise ResidueFormatError(
                        f"compression set at 0x{offset:x} is past the end of the file"
                    )
                handle.seek(offset)
                set_header = handle.read(4 + HIBR_MAX_PAGES_PER_SET * descriptor_size)
                (set_status,) = struct.unpack_from("<I", set_header, 0)
                descriptor_count = set_status & 0xFF
                # Compressed size: bits 8-28 (Volatility hib layer; bit 29 joins it before
                # Windows 11 24H2 but is not part of it there). A set holds at most 16 pages
                # (64 KiB), so the masked-off bit is never legitimately set.
                compressed_size = (set_status >> 8) & 0x1FFFFF
                huffman = bool(set_status & 0xC0000000)
                if (
                    not descriptor_count
                    or descriptor_count > HIBR_MAX_PAGES_PER_SET
                    or not compressed_size
                ):
                    raise ResidueFormatError(
                        f"corrupt compression set header at 0x{offset:x}"
                    )
                if len(set_header) < 4 + descriptor_count * descriptor_size:
                    raise ResidueFormatError(
                        f"truncated compression set descriptors at 0x{offset:x}"
                    )
                page_numbers: list[int] = []
                for index in range(descriptor_count):
                    raw = int.from_bytes(
                        set_header[
                            4 + index * descriptor_size : 4
                            + (index + 1) * descriptor_size
                        ],
                        "little",
                    )
                    page_numbers.extend(range(raw >> 4, (raw >> 4) + (raw & 0xF) + 1))
                if (
                    len(page_numbers) > HIBR_MAX_PAGES_PER_SET
                    or compressed_size > HIBR_MAX_COMPRESSED_BYTES
                ):
                    raise ResidueFormatError(
                        f"compression set at 0x{offset:x} exceeds 16 pages"
                    )
                data_offset = offset + 4 + descriptor_count * descriptor_size
                handle.seek(data_offset)
                compressed = handle.read(compressed_size)
                if len(compressed) != compressed_size:
                    raise ResidueFormatError(
                        f"compression set data at 0x{data_offset:x} is truncated"
                    )
                expected = len(page_numbers) * RESIDUE_PAGE_SIZE
                try:
                    if compressed_size == expected:
                        plain = compressed
                    elif huffman:
                        plain = xpress_huffman.decompress(compressed, expected)
                    else:
                        plain = xpress_lz77.decompress(compressed, expected)
                except (
                    xpress_huffman.XpressHuffmanError,
                    xpress_lz77.XpressLz77Error,
                ) as exc:
                    raise ResidueFormatError(
                        f"compression set at 0x{offset:x} failed to decompress: {exc}"
                    ) from exc
                for index, page_number in enumerate(page_numbers):
                    yield (
                        page_number,
                        offset,
                        plain[
                            index * RESIDUE_PAGE_SIZE : (index + 1) * RESIDUE_PAGE_SIZE
                        ],
                    )
                status.pages_read += len(page_numbers)
                remaining -= len(page_numbers)
                offset = data_offset + compressed_size


def iter_hiberfil_segments(
    source: Path, status: ResidueSourceStatus, segment_bytes: int
) -> Iterator[tuple[bytes, list[tuple[int, int, int]], int, int]]:
    """Decompressed pages in bounded segments, overlapping like the raw page reader.

    A segment is cut once it holds ``segment_bytes`` plus the overlap; its last
    overlap pages are carried into the next segment, which owns them, so a hit
    that starts near a boundary is scanned with its following bytes.
    """
    overlap = (
        min(RESIDUE_SEGMENT_OVERLAP_BYTES, segment_bytes // 2)
        // RESIDUE_PAGE_SIZE
        * RESIDUE_PAGE_SIZE
    )
    buffer = bytearray()
    pages: list[tuple[int, int, int]] = []
    try:
        for page_number, set_offset, page in iter_hiberfil_pages(source, status):
            pages.append((len(buffer), set_offset, page_number))
            buffer += page
            if len(buffer) >= segment_bytes + overlap:
                owned_end = len(buffer) - overlap
                yield bytes(buffer), pages, 0, owned_end
                pages = [
                    (offset - owned_end, file_offset, number)
                    for offset, file_offset, number in pages
                    if offset >= owned_end
                ]
                buffer = bytearray(buffer[owned_end:])
    except ResidueFormatError:
        if buffer:
            yield bytes(buffer), pages, 0, len(buffer)
        raise
    if buffer:
        yield bytes(buffer), pages, 0, len(buffer)
