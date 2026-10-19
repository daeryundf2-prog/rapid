"""Unallocated clusters of an NTFS volume inside a disk image (R6 S2 갈래 C).

``$Boot`` (cluster size, total sectors) and ``$Bitmap`` (one bit per cluster, set = allocated)
give the unallocated cluster runs (adjacent clusters merged, at most ``MAX_RUNS`` runs). The
image is read directly -- raw/dd images with ``open`` (stdlib), E01/Ex01 through pyewf
(``core.e01_native.EwfSectorReader``) -- and ``iter_unallocated_chunks`` streams the runs in
``CHUNK_BYTES`` windows with an ``OVERLAP_BYTES`` overlap inside a run (the window shape
``core.url_carving.scan_url_source`` uses), every window carrying its **absolute image byte
offset** so a hit maps back to the image and to its cluster (``UnallocatedImage.cluster_at``).

``$Bitmap`` comes from Sleuth Kit ``icat`` (inode 6) when it is installed, else from MFT record
6 read natively (VBR ``mft_lcn`` -> FILE record -> unnamed ``$DATA`` runlist). The source image
is only read. Nothing here writes outside the caller's work folder.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ntfs_volume import apply_fixups, parse_ntfs_vbr

CHUNK_BYTES = 8 * 1024 * 1024
OVERLAP_BYTES = 8 * 1024
MAX_RUNS = 2_000_000
BITMAP_INODE = 6
# $Bitmap of a 16 TiB volume with 4 KiB clusters is 512 MiB; refuse anything larger.
MAX_BITMAP_BYTES = 512 * 1024 * 1024
READ_BLOCK_BYTES = 1024 * 1024
BITMAP_SCAN_BYTES = 4 * 1024 * 1024

StreamRunner = Callable[[Sequence[str], Path], "subprocess.CompletedProcess[bytes]"]


class NtfsUnallocError(RuntimeError):
    """``str(exc)`` is the Korean reason shown to the examiner."""


@dataclass
class UnallocatedRuns:
    runs: list[tuple[int, int]]
    truncated: bool
    free_clusters: int


@dataclass
class ScanStats:
    bytes_read: int = 0
    windows: int = 0


@dataclass
class Window:
    data: bytes
    image_offset: int
    cutoff: int


def _clear_bit_runs(value: int) -> tuple[tuple[int, int], ...]:
    """``(first bit, end bit)`` runs of clear bits of one bitmap byte (LSB first)."""
    out: list[tuple[int, int]] = []
    bit = 0
    while bit < 8:
        if value & (1 << bit):
            bit += 1
            continue
        first = bit
        while bit < 8 and not value & (1 << bit):
            bit += 1
        out.append((first, bit))
    return tuple(out)


# Per-byte lookup table: the clear-bit runs of every byte value (R6 S2 review: no bit loop).
_CLEAR_BIT_RUNS = tuple(_clear_bit_runs(value) for value in range(256))
_BITMAP_RUN_PATTERN = re.compile(rb"\x00+|[^\x00\xff]+")


def _count_free_clusters(view: memoryview, total_clusters: int, limit_bytes: int, check_cancel: Callable[[], None] | None) -> int:
    """Clear bits among the first ``total_clusters`` bits (popcount per block, not per bit)."""
    full_bytes = min(limit_bytes, total_clusters // 8)
    free = 0
    for position in range(0, full_bytes, BITMAP_SCAN_BYTES):
        if check_cancel is not None:
            check_cancel()
        block = view[position : min(position + BITMAP_SCAN_BYTES, full_bytes)]
        free += len(block) * 8 - int.from_bytes(block, "little").bit_count()
    if full_bytes < limit_bytes:
        value = view[full_bytes]
        free += sum(1 for bit in range(total_clusters - full_bytes * 8) if not value & (1 << bit))
    return free


def bitmap_unallocated_runs(
    bitmap: bytes,
    total_clusters: int,
    *,
    max_runs: int = MAX_RUNS,
    check_cancel: Callable[[], None] | None = None,
) -> UnallocatedRuns:
    """Merged ``(first cluster, cluster count)`` runs of clear bits among the first ``total_clusters``
    bits of ``bitmap`` (bit ``n`` = byte ``n // 8``, bit ``n % 8``, LSB first). ``free_clusters``
    counts every clear bit even past ``max_runs`` (a popcount per block once the run list is full).

    0x00 / 0xFF byte runs are taken whole; any other byte uses a per-byte run table.
    ``check_cancel`` is called once per ``BITMAP_SCAN_BYTES`` block."""
    total_clusters = max(int(total_clusters), 0)
    view = memoryview(bitmap).cast("B") if not isinstance(bitmap, bytes) else memoryview(bitmap)
    limit_bytes = min(len(view), (total_clusters + 7) // 8)
    free = _count_free_clusters(view, total_clusters, limit_bytes, check_cancel)
    runs: list[tuple[int, int]] = []
    truncated = False
    current_start = -1
    current_end = -1
    table = _CLEAR_BIT_RUNS
    for position in range(0, limit_bytes, BITMAP_SCAN_BYTES):
        if truncated:
            break
        if check_cancel is not None:
            check_cancel()
        block = bytes(view[position : min(position + BITMAP_SCAN_BYTES, limit_bytes)])
        for match in _BITMAP_RUN_PATTERN.finditer(block):
            first_byte = match.start()
            if block[first_byte] == 0:
                start, end = (position + first_byte) * 8, min((position + match.end()) * 8, total_clusters)
                if start == current_end:
                    current_end = end
                    continue
                if current_start >= 0:
                    if len(runs) >= max_runs:
                        truncated = True
                        break
                    runs.append((current_start, current_end - current_start))
                current_start, current_end = start, end
                continue
            base = (position + first_byte) * 8
            for value in block[first_byte : match.end()]:
                for low, high in table[value]:
                    start, end = base + low, base + high
                    if end > total_clusters:
                        end = total_clusters
                        if end <= start:
                            break
                    if start == current_end:
                        current_end = end
                        continue
                    if current_start >= 0:
                        if len(runs) >= max_runs:
                            truncated = True
                            break
                        runs.append((current_start, current_end - current_start))
                    current_start, current_end = start, end
                if truncated:
                    break
                base += 8
            if truncated:
                break
    if current_start >= 0 and not truncated:
        if len(runs) >= max_runs:
            truncated = True
        else:
            runs.append((current_start, current_end - current_start))
    return UnallocatedRuns(runs=runs, truncated=truncated, free_clusters=free)


def decode_runlist(blob: bytes) -> list[tuple[int | None, int]]:
    """``(lcn or None for sparse, cluster count)`` of an NTFS runlist (stops at the terminator)."""
    runs: list[tuple[int | None, int]] = []
    offset = 0
    lcn = 0
    while offset < len(blob):
        header = blob[offset]
        if header == 0:
            break
        length_size, delta_size = header & 0x0F, header >> 4
        end = offset + 1 + length_size + delta_size
        if length_size == 0 or length_size > 8 or delta_size > 8 or end > len(blob):
            raise NtfsUnallocError("$Bitmap 데이터 런 목록이 손상되었습니다")
        count = int.from_bytes(blob[offset + 1 : offset + 1 + length_size], "little")
        if delta_size:
            lcn += int.from_bytes(blob[offset + 1 + length_size : end], "little", signed=True)
            runs.append((lcn, count))
        else:
            runs.append((None, count))
        offset = end
    return runs


def bitmap_data_attribute(record: bytes, sector_size: int) -> tuple[bytes | None, list[tuple[int | None, int]], int]:
    """``(resident content or None, runlist, data size)`` of the unnamed ``$DATA`` of a FILE record."""
    data = apply_fixups(record, sector_size if sector_size in (512, 1024, 2048, 4096) else 512)
    if data is None:
        raise NtfsUnallocError("$Bitmap MFT 레코드(#6)가 FILE 레코드가 아닙니다")
    offset = int.from_bytes(data[0x14:0x16], "little")
    for _ in range(64):
        if not 0 < offset < len(data) - 16:
            break
        attr_type = int.from_bytes(data[offset : offset + 4], "little")
        if attr_type == 0xFFFFFFFF:
            break
        length = int.from_bytes(data[offset + 4 : offset + 8], "little")
        if length < 16 or offset + length > len(data):
            break
        if attr_type == 0x80 and data[offset + 9] == 0:  # unnamed $DATA
            attr = data[offset : offset + length]
            if attr[8] == 0:
                content_length = int.from_bytes(attr[0x10:0x14], "little")
                content_offset = int.from_bytes(attr[0x14:0x16], "little")
                content = attr[content_offset : content_offset + content_length]
                return content, [], len(content)
            runlist_offset = int.from_bytes(attr[0x20:0x22], "little")
            data_size = int.from_bytes(attr[0x30:0x38], "little")
            return None, decode_runlist(attr[runlist_offset:]), data_size
        offset += length
    raise NtfsUnallocError("$Bitmap MFT 레코드(#6)에 $DATA 속성이 없습니다")


class _BlockCache:
    """Read-through cache of ``READ_BLOCK_BYTES`` aligned blocks (many small runs share one read)."""

    def __init__(self, reader: Any) -> None:
        self.reader = reader
        self.block_index = -1
        self.block = b""

    def read(self, offset: int, size: int) -> bytes:
        if size >= READ_BLOCK_BYTES:
            self.reader.seek(offset)
            return self.reader.read(size)
        out = bytearray()
        while size > 0:
            index = offset // READ_BLOCK_BYTES
            if index != self.block_index:
                self.reader.seek(index * READ_BLOCK_BYTES)
                self.block = self.reader.read(READ_BLOCK_BYTES)
                self.block_index = index
            start = offset - index * READ_BLOCK_BYTES
            piece = self.block[start : start + size]
            if not piece:
                break
            out += piece
            offset += len(piece)
            size -= len(piece)
        return bytes(out)


def iter_unallocated_chunks(
    reader: Any,
    partition_offset: int,
    cluster_size: int,
    runs: Sequence[tuple[int, int]],
    read_limit: int,
    *,
    stats: ScanStats | None = None,
    chunk_bytes: int = CHUNK_BYTES,
    overlap_bytes: int = OVERLAP_BYTES,
    check_cancel: Callable[[], None] | None = None,
) -> Iterator[Window]:
    """Windows over the unallocated runs, at most ``read_limit`` new bytes in all.

    Inside one run each window is the unprocessed tail of the previous one plus ``chunk_bytes``
    new bytes; a match starting before ``cutoff`` belongs to this window (the last window of a run
    takes everything). ``image_offset`` is the absolute image byte offset of ``data[0]``."""
    stats = stats if stats is not None else ScanStats()
    cache = _BlockCache(reader)
    budget = read_limit
    for first_cluster, count in runs:
        if budget <= 0:
            break
        position = partition_offset + first_cluster * cluster_size
        end = position + count * cluster_size
        tail = b""
        while position < end and budget > 0:
            if check_cancel is not None:
                check_cancel()
            want = min(chunk_bytes, end - position, budget)
            data = cache.read(position, want)
            if not data:
                break
            position += len(data)
            budget -= len(data)
            stats.bytes_read += len(data)
            final = position >= end or budget <= 0 or len(data) < want
            window = tail + data
            cutoff = len(window) if final else max(len(window) - overlap_bytes, 0)
            stats.windows += 1
            yield Window(window, position - len(window), cutoff)
            tail = window[cutoff:]
            if final:
                break


@dataclass
class UnallocatedImage:
    """An opened image positioned on its NTFS partition with the unallocated runs computed."""

    image: Path
    reader: Any
    media_kind: str
    partition: dict[str, object]
    vbr: dict[str, object]
    runs: UnallocatedRuns
    bitmap_method: str
    cluster_size: int
    total_clusters: int
    notes: list[str] = field(default_factory=list)

    @property
    def partition_offset(self) -> int:
        return int(self.partition["byte_offset"])  # type: ignore[call-overload]

    @property
    def unallocated_bytes(self) -> int:
        return self.runs.free_clusters * self.cluster_size

    def cluster_at(self, image_offset: int) -> int:
        return (image_offset - self.partition_offset) // self.cluster_size

    def windows(self, read_limit: int, *, stats: ScanStats, check_cancel: Callable[[], None] | None = None) -> Iterator[Window]:
        return iter_unallocated_chunks(
            self.reader, self.partition_offset, self.cluster_size, self.runs.runs, read_limit,
            stats=stats, check_cancel=check_cancel,
        )


def _read_bitmap_native(reader: Any, partition_offset: int, vbr: dict[str, object], total_clusters: int) -> bytes:
    cluster_size = int(vbr["cluster_size"])  # type: ignore[call-overload]
    record_size = vbr.get("mft_record_size")
    record_size = record_size if isinstance(record_size, int) and record_size in (1024, 2048, 4096) else 1024
    mft_offset = partition_offset + int(vbr["mft_lcn"]) * cluster_size  # type: ignore[call-overload]
    reader.seek(mft_offset + BITMAP_INODE * record_size)
    record = reader.read(record_size)
    content, runlist, data_size = bitmap_data_attribute(record, int(vbr.get("bytes_per_sector") or 512))  # type: ignore[call-overload]
    if content is not None:
        return content
    wanted = min(data_size, (total_clusters + 7) // 8)
    if wanted > MAX_BITMAP_BYTES:
        raise NtfsUnallocError(f"$Bitmap이 너무 큽니다({wanted:,}바이트 > {MAX_BITMAP_BYTES:,})")
    out = bytearray()
    for lcn, count in runlist:
        if len(out) >= wanted:
            break
        size = min(count * cluster_size, wanted - len(out))
        if lcn is None:
            out += bytes(size)
            continue
        if lcn < 0 or lcn + count > total_clusters:
            # R6 S2 review: a corrupt runlist (negative / past-the-volume LCN) is a Korean error,
            # never a negative seek (ValueError) escaping the analysis.
            raise NtfsUnallocError(
                f"$Bitmap 데이터 런의 클러스터 번호({lcn:,}, {count:,}개)가 볼륨 범위(0~{total_clusters:,}) 밖입니다(손상된 MFT 레코드)"
            )
        reader.seek(partition_offset + lcn * cluster_size)
        piece = reader.read(size)
        if len(piece) < size:
            raise NtfsUnallocError("$Bitmap을 끝까지 읽지 못했습니다(이미지가 잘림)")
        out += piece
    if len(out) < wanted:
        raise NtfsUnallocError("$Bitmap 데이터 런이 볼륨 클러스터 수보다 짧습니다")
    return bytes(out)


def _read_bitmap_icat(
    image: Path, start_sector: int, work_dir: Path, stream_runner: StreamRunner
) -> bytes | None:
    """``icat -o <sector> <image> 6`` into ``work_dir``; ``None`` when icat fails."""
    from .ntfs_metadata import run_stream_capped

    out = work_dir / "Bitmap.bin"
    work_dir.mkdir(parents=True, exist_ok=True)
    command = ["icat", "-o", str(start_sector), str(image), str(BITMAP_INODE)]
    try:
        # The default runner kills icat once the stream passes the cap (never written in full).
        result, capped, _size = run_stream_capped(stream_runner, command, out, MAX_BITMAP_BYTES)
        if capped:
            raise NtfsUnallocError(f"$Bitmap이 너무 큽니다(> {MAX_BITMAP_BYTES:,}바이트)")
        if result.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
            return None
        return out.read_bytes()
    finally:
        out.unlink(missing_ok=True)


def _default_stream_runner(command: Sequence[str], output_path: Path) -> subprocess.CompletedProcess[bytes]:
    from .ntfs_metadata import default_stream_runner

    return default_stream_runner(command, output_path)


_default_stream_runner.supports_max_bytes = True  # type: ignore[attr-defined]


@contextlib.contextmanager
def open_unallocated_image(
    image: Path,
    *,
    partition_start_sector: int | None = None,
    work_dir: Path,
    max_runs: int = MAX_RUNS,
    stream_runner: StreamRunner = _default_stream_runner,
    tool_resolver: Callable[[str], str | None] = shutil.which,
    check_cancel: Callable[[], None] | None = None,
) -> Iterator[UnallocatedImage]:
    """Open ``image``, find its NTFS partition, read ``$Boot`` and ``$Bitmap`` and compute the runs.

    Raises ``NtfsUnallocError`` (Korean) for every expected failure: no pyewf for an E01, no NTFS
    partition, a corrupt ``$Bitmap``."""
    from .e01_native import (
        EwfSectorReader,
        NativeImageError,
        locate_ntfs_partition,
        open_image_media,
    )

    try:
        with open_image_media(image) as (handle, media_kind):
            try:
                partition = locate_ntfs_partition(handle, partition_start_sector)
            except NativeImageError as exc:
                raise NtfsUnallocError(str(exc)) from exc
            reader = EwfSectorReader(handle)
            reader.seek(int(partition["byte_offset"]))  # type: ignore[call-overload]
            vbr = parse_ntfs_vbr(reader.read(512))
            cluster_size = vbr.get("cluster_size")
            if vbr.get("vbr_parse_status") != "parsed" or not isinstance(cluster_size, int) or cluster_size <= 0:
                raise NtfsUnallocError("NTFS 부트 섹터에서 클러스터 크기를 읽지 못했습니다")
            total_clusters = int(vbr.get("total_sectors") or 0) * int(vbr.get("bytes_per_sector") or 0) // cluster_size  # type: ignore[call-overload]
            if total_clusters <= 0:
                raise NtfsUnallocError("NTFS 부트 섹터의 총 섹터 수가 0입니다")
            bitmap: bytes | None = None
            method = "native-mft-record-6"
            if tool_resolver("icat") is not None:
                # icat ``-o`` counts 512-byte sectors; the byte offset keeps 4Kn partitions right.
                icat_sector = int(partition["byte_offset"]) // 512  # type: ignore[call-overload]
                bitmap = _read_bitmap_icat(Path(image), icat_sector, work_dir, stream_runner)
                method = "sleuthkit-icat"
            if bitmap is None:
                bitmap = _read_bitmap_native(reader, int(partition["byte_offset"]), vbr, total_clusters)  # type: ignore[call-overload]
                method = "native-mft-record-6"
            runs = bitmap_unallocated_runs(bitmap, total_clusters, max_runs=max_runs, check_cancel=check_cancel)
            del bitmap
            yield UnallocatedImage(
                image=Path(image),
                reader=reader,
                media_kind=media_kind,
                partition=partition,
                vbr=vbr,
                runs=runs,
                bitmap_method=method,
                cluster_size=cluster_size,
                total_clusters=total_clusters,
            )
    except NativeImageError as exc:
        raise NtfsUnallocError(str(exc)) from exc
    except OSError as exc:
        raise NtfsUnallocError(f"이미지를 읽을 수 없습니다: {exc}") from exc
    except (ValueError, OverflowError) as exc:
        raise NtfsUnallocError(f"NTFS 구조 값이 비정상입니다(손상된 부트 섹터·MFT 레코드): {exc}") from exc


def boot_mft_consistency(boot: bytes, mft_head: bytes, mft_record_size: int) -> tuple[str, str]:
    """``(verdict, Korean reason)`` of an extracted ``$Boot`` against an extracted ``$MFT``
    (R6 S2 review: a sibling ``$Boot`` from another volume is never used).

    ``verdict``: ``"match"`` (the first data run of ``$MFT`` record 0 -- the ``$MFT``'s own
    ``$DATA`` -- starts at the boot sector's ``mft_lcn`` and the MFT record sizes agree),
    ``"mismatch"`` (not an NTFS boot sector, or record size / MFT LCN differ: skip it) or
    ``"unverified"`` (record 0 carries no readable runlist, e.g. a partial export)."""
    vbr = parse_ntfs_vbr(boot[:512])
    if vbr.get("vbr_parse_status") != "parsed":
        return "mismatch", "$Boot 파일이 NTFS 부트 섹터가 아닙니다"
    boot_record_size = vbr.get("mft_record_size")
    if isinstance(boot_record_size, int) and boot_record_size != mft_record_size:
        return "mismatch", f"$Boot의 MFT 레코드 크기({boot_record_size})가 $MFT({mft_record_size})와 다릅니다(다른 볼륨)"
    try:
        content, runlist, _size = bitmap_data_attribute(
            mft_head[:mft_record_size], int(vbr.get("bytes_per_sector") or 512)  # type: ignore[call-overload]
        )
    except NtfsUnallocError:
        return "unverified", "$MFT 레코드 0의 $DATA를 읽지 못해 $Boot와 같은 볼륨인지 확인하지 못했습니다"
    first_lcn = next((lcn for lcn, _count in runlist if lcn is not None), None)
    if content is not None or first_lcn is None:
        return "unverified", "$MFT 레코드 0에 데이터 런이 없어 $Boot와 같은 볼륨인지 확인하지 못했습니다"
    if first_lcn != vbr.get("mft_lcn"):
        return "mismatch", f"$Boot의 MFT 시작 클러스터({vbr.get('mft_lcn')})가 $MFT 레코드 0의 위치({first_lcn})와 다릅니다(다른 볼륨)"
    return "match", ""
