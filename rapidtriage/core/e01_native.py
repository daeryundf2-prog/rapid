"""Native E01/Ex01 decoding path (pyewf + dissect.ntfs, no external tools).

Used as a fallback when ewfmount/Sleuth Kit are unavailable. Reads EWF
segment sets directly through pyewf, parses MBR/GPT partition tables
natively, and walks NTFS via dissect.ntfs to recover files.

This is an engineering-grade path: emitted provenance marks results
``python-native-ewf`` so downstream records keep the distinction between
trusted-tool extraction (ewfmount/tsk_recover) and native decode.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import struct
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .coverage import record_coverage

try:  # optional native decoders
    import pyewf  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - environment dependent
    pyewf = None

try:
    from dissect.ntfs import NTFS  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - environment dependent
    NTFS = None

NATIVE_MOUNT_STRATEGY = "python-native-ewf"

GPT_HEADER_SIGNATURE = b"EFI PART"
MBR_BOOT_SIGNATURE = 0xAA55  # bytes 55 AA read as little-endian u16
MBR_GPT_PROTECTIVE = 0xEE

# GPT partition-type GUIDs → mmls-style description strings (the strings are
# matched by guess_partition_filesystem / is_supported_mmls_description).
GPT_TYPE_DESCRIPTIONS = {
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic data partition",
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI system partition",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved partition",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery environment",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "Logical Disk Manager metadata partition",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "Logical Disk Manager data partition",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "e75caf8f-f680-4cee-afa3-b001e56efc2d": "Linux LVM",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "55465300-0000-11aa-aa11-00306543ecac": "Apple UFS",
    "426f6f74-0000-11aa-aa11-00306543ecac": "Apple boot",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
}

MBR_TYPE_DESCRIPTIONS = {
    0x07: "NTFS / exFAT",
    0x0B: "Win95 FAT32",
    0x0C: "Win95 FAT32 (LBA)",
    0x0E: "Win95 FAT16 (LBA)",
    0x06: "FAT16",
    0x01: "FAT12",
    0x04: "FAT16",
    0x0F: "Extended partition (LBA)",
    0x05: "Extended partition",
    0x82: "Linux swap",
    0x83: "Linux filesystem",
    0x8E: "Linux LVM",
    0x27: "Windows recovery environment",
    0xEF: "EFI system partition",
    0xEE: "GPT protective",
    0xAF: "Apple HFS+",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA9: "NetBSD",
}

SWAP_DESCRIPTIONS = ("swap",)
MAX_NATIVE_EXTRACT_FILES = 200_000
MAX_NATIVE_EXTRACT_BYTES = 0  # 0 = unbounded; callers may cap later
NATIVE_MAX_EXTRACT_FILES_ENV = "RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES"


def native_extract_file_limit() -> int:
    """Active per-image extraction cap; env override for large real evidence."""
    raw = os.environ.get(NATIVE_MAX_EXTRACT_FILES_ENV, "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return MAX_NATIVE_EXTRACT_FILES


NATIVE_E01_WORKERS_ENV = "RAPIDTRIAGE_E01_WORKERS"
DIGEST_ALGORITHMS = ("md5", "sha1", "sha256")


def native_extract_worker_count() -> int:
    """Extraction worker count: env override, else ``min(8, cpu_count)``."""
    raw = os.environ.get(NATIVE_E01_WORKERS_ENV, "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return max(1, min(8, os.cpu_count() or 1))


def native_e01_available() -> bool:
    return pyewf is not None and NTFS is not None


def native_e01_missing_modules() -> list[str]:
    missing = []
    if pyewf is None:
        missing.append("pyewf")
    if NTFS is None:
        missing.append("dissect.ntfs")
    return missing


class EwfSectorReader(io.RawIOBase):
    """Seekable read-only file-like view over a pyewf handle.

    ``base`` is the byte offset where the exposed region starts (used to
    present a partition as a zero-based stream for dissect.ntfs).
    """

    def __init__(self, handle: Any, base: int = 0, size: int | None = None):
        self._handle = handle
        self._base = base
        self._size = size if size is not None else int(handle.get_media_size()) - base
        self._pos = 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new = offset
        elif whence == io.SEEK_CUR:
            new = self._pos + offset
        else:
            new = self._size + offset
        if new < 0:
            raise ValueError("negative seek position")
        self._pos = new
        return self._pos

    def tell(self) -> int:
        return self._pos

    def readinto(self, buf) -> int:
        if self._pos >= self._size:
            return 0
        want = min(len(buf), self._size - self._pos)
        self._handle.seek(self._base + self._pos)
        data = self._handle.read(want)
        n = len(data)
        buf[:n] = data
        self._pos += n
        return n


def open_ewf_segments(segments: list[Path]) -> Any:
    if pyewf is None:
        raise RuntimeError("pyewf is not importable")
    handle = pyewf.handle()
    handle.open([str(s) for s in segments])
    return handle


class RawMediaHandle:
    """pyewf-handle-shaped view of a raw/dd image file (stdlib), for ``native_partition_table``.

    ``bytes_per_sector`` is 512 unless the image is a 4Kn GPT disk (``EFI PART`` at byte 4096
    and not at byte 512), where it is 4096."""

    bytes_per_sector = 512

    def __init__(self, path: Path):
        self._file = Path(path).open("rb")
        self._size = os.fstat(self._file.fileno()).st_size
        head = self._file.read(4096 + 8)
        self._file.seek(0)
        if head[512:520] != GPT_SIGNATURE and head[4096:4104] == GPT_SIGNATURE:
            self.bytes_per_sector = 4096

    def get_media_size(self) -> int:
        return self._size

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._file.seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        return self._file.read(size)

    def close(self) -> None:
        self._file.close()


class NativeImageError(RuntimeError):
    """A native image read that cannot go on; ``str(exc)`` is the Korean reason shown to the examiner."""


EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
GPT_SIGNATURE = b"EFI PART"
NTFS_OEM_ID = b"NTFS    "


def is_ewf_file(path: Path) -> bool:
    try:
        with Path(path).open("rb") as handle:
            return handle.read(8) == EWF_SIGNATURE
    except OSError:
        return False


@contextlib.contextmanager
def open_image_media(image: Path):
    """Yield ``(handle, media_kind)`` for an E01/Ex01 segment set (pyewf) or a raw image (stdlib).

    Raises ``NativeImageError`` (Korean) when an EWF image needs pyewf and it is missing."""
    from .e01 import discover_e01_segments

    if is_ewf_file(image):
        if pyewf is None:
            raise NativeImageError(
                "E01 이미지를 직접 읽으려면 pyewf(libewf-python)가 필요합니다. pyewf를 설치하거나 Sleuth Kit을 설치하세요"
            )
        try:
            handle = open_ewf_segments(discover_e01_segments(Path(image)))
        except Exception as exc:  # pyewf raises IOError/OSError subclasses with C messages
            raise NativeImageError(f"E01 이미지를 열 수 없습니다: {exc}") from exc
        kind = "ewf"
    else:
        try:
            handle = RawMediaHandle(Path(image))
        except OSError as exc:
            raise NativeImageError(f"이미지를 열 수 없습니다: {exc}") from exc
        kind = "raw"
    try:
        yield handle, kind
    finally:
        with contextlib.suppress(Exception):
            handle.close()


def locate_ntfs_partition(handle: Any, partition_start_sector: int | None = None) -> dict[str, object]:
    """The NTFS partition of an opened image: ``start_sector``, ``byte_offset``, ``sector_size_bytes``,
    ``description``, ``selection_method``. A volume image (VBR at offset 0) is its own partition.

    Raises ``NativeImageError`` (Korean) when the requested sector holds no NTFS boot sector or
    no partition does."""
    reader = EwfSectorReader(handle)
    sector_size = ewf_sector_size(handle)

    def oem_at(byte_offset: int) -> bytes:
        reader.seek(byte_offset + 3)
        return reader.read(8)

    if partition_start_sector is not None:
        offset = partition_start_sector * sector_size
        if oem_at(offset) != NTFS_OEM_ID and sector_size == 512 and oem_at(partition_start_sector * 4096) == NTFS_OEM_ID:
            # 4Kn media whose sector size the container does not record: sectors are 4096 bytes.
            sector_size, offset = 4096, partition_start_sector * 4096
        if oem_at(offset) != NTFS_OEM_ID:
            raise NativeImageError(
                f"지정한 파티션 시작 섹터 {partition_start_sector}에 NTFS 부트 섹터가 없습니다(파티션이 아니거나 NTFS가 아님)"
            )
        return {
            "start_sector": partition_start_sector,
            "byte_offset": offset,
            "sector_size_bytes": sector_size,
            "description": "",
            "selection_method": "operator-specified",
        }
    if oem_at(0) == NTFS_OEM_ID:
        return {
            "start_sector": 0,
            "byte_offset": 0,
            "sector_size_bytes": sector_size,
            "description": "NTFS volume image",
            "selection_method": "volume-image",
        }
    partitions, sector_size = native_partition_table(handle)
    for row in sorted(partitions, key=lambda item: -int(item.get("sector_count") or 0)):
        offset = int(row.get("byte_offset") or 0)
        row_sector_size = sector_size
        if oem_at(offset) != NTFS_OEM_ID and sector_size == 512:
            # 4Kn MBR disk read as 512-byte sectors: the table's LBAs count 4096-byte sectors.
            offset_4k = int(row.get("start_sector") or 0) * 4096
            if offset_4k and oem_at(offset_4k) == NTFS_OEM_ID:
                offset, row_sector_size = offset_4k, 4096
        if oem_at(offset) == NTFS_OEM_ID:
            return {
                "start_sector": int(row.get("start_sector") or 0),
                "byte_offset": offset,
                "sector_size_bytes": row_sector_size,
                "description": str(row.get("description") or ""),
                "selection_method": "ntfs-oem-id-probe",
            }
    raise NativeImageError("이미지에서 NTFS 파티션을 찾지 못했습니다(디스크 이미지가 아니거나 NTFS 파티션이 없음)")


def dump_boot_sector(image: Path, out_path: Path, *, partition_start_sector: int | None = None) -> dict[str, object]:
    """Copy the first sector (512 bytes) of the image's NTFS partition to ``out_path``.

    The native fallback of ``ntfs-meta`` when Sleuth Kit is absent: raw images need nothing,
    E01/Ex01 images pyewf (``EwfSectorReader``). Returns the ``outputs.boot`` manifest entry
    plus ``partition``; raises ``NativeImageError`` (Korean)."""
    import hashlib

    with open_image_media(image) as (handle, media_kind):
        partition = locate_ntfs_partition(handle, partition_start_sector)
        reader = EwfSectorReader(handle)
        reader.seek(int(partition["byte_offset"]))  # type: ignore[call-overload]
        boot = reader.read(512)
    if len(boot) < 512:
        raise NativeImageError("NTFS 부트 섹터를 끝까지 읽지 못했습니다(이미지가 잘림)")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(boot)
    return {
        "path": str(out_path),
        "size_bytes": len(boot),
        "sha256": hashlib.sha256(boot).hexdigest(),
        "extraction_mode": f"native-boot-sector-{media_kind}",
        "partition": {**partition, "filesystem_guess": "ntfs", "filesystem_verified": True},
    }


def ewf_sector_size(handle: Any) -> int:
    size = int(getattr(handle, "bytes_per_sector", 0) or 0)
    return size if size > 0 else 512


def _guid_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def _mbr_partitions(sector0: bytes, sector_size: int) -> list[dict[str, object]]:
    parts: list[dict[str, object]] = []
    for index in range(4):
        entry = sector0[0x1BE + index * 16 : 0x1BE + (index + 1) * 16]
        ptype = entry[4]
        start_lba, count = struct.unpack_from("<II", entry, 8)
        if ptype == 0 or count == 0:
            continue
        if ptype == MBR_GPT_PROTECTIVE:
            continue  # real layout lives in the GPT
        description = MBR_TYPE_DESCRIPTIONS.get(ptype, f"0x{ptype:02x}")
        if ptype in (0x05, 0x0F):
            continue  # extended container; logical drives parsed separately
        parts.append(
            {
                "slot": index,
                "partition_number": index,
                "start_sector": start_lba,
                "sector_count": count,
                "sector_size_bytes": sector_size,
                "byte_offset": start_lba * sector_size,
                "size_bytes": count * sector_size,
                "description": description,
                "boot_flag": entry[0] == 0x80,
            }
        )
    return parts


def _gpt_partitions(reader: EwfSectorReader, sector_size: int) -> list[dict[str, object]]:
    reader.seek(sector_size)
    header = reader.read(sector_size)
    if len(header) < 92 or header[:8] != GPT_HEADER_SIGNATURE:
        return []
    entry_lba, entry_count, entry_size = struct.unpack_from("<QII", header, 72)
    if entry_size < 128 or entry_count > 4096:
        return []
    parts: list[dict[str, object]] = []
    reader.seek(entry_lba * sector_size)
    entries = reader.read(entry_count * entry_size)
    for index in range(entry_count):
        entry = entries[index * entry_size : (index + 1) * entry_size]
        if len(entry) < 128:
            break
        type_guid = _guid_le(entry[:16])
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        description = GPT_TYPE_DESCRIPTIONS.get(type_guid, name or f"gpt-{type_guid}")
        count = last_lba - first_lba + 1
        parts.append(
            {
                "slot": index,
                "partition_number": index,
                "start_sector": first_lba,
                "sector_count": count,
                "sector_size_bytes": sector_size,
                "byte_offset": first_lba * sector_size,
                "size_bytes": count * sector_size,
                "description": description,
                "gpt_type_guid": type_guid,
                "gpt_name": name,
                "boot_flag": False,
            }
        )
    return parts


def native_partition_table(handle: Any) -> tuple[list[dict[str, object]], int]:
    """Parse MBR or GPT from a pyewf handle → mmls-shaped partition rows."""
    sector_size = ewf_sector_size(handle)
    reader = EwfSectorReader(handle)
    reader.seek(0)
    sector0 = reader.read(sector_size)
    if len(sector0) < sector_size or struct.unpack_from("<H", sector0, 510)[0] != MBR_BOOT_SIGNATURE:
        # No partition table — treat the whole media as one filesystem extent
        # (some images are volume images rather than full disks).
        media_sectors = int(handle.get_media_size()) // sector_size
        return [
            {
                "slot": 0,
                "partition_number": 0,
                "start_sector": 0,
                "sector_count": media_sectors,
                "sector_size_bytes": sector_size,
                "byte_offset": 0,
                "size_bytes": media_sectors * sector_size,
                "description": "Basic data partition",
                "boot_flag": False,
                "whole_media": True,
            }
        ], sector_size
    parts = _gpt_partitions(reader, sector_size)
    if not parts:
        parts = _mbr_partitions(sector0, sector_size)
    return parts, sector_size


def _is_supported_partition(row: dict[str, object]) -> bool:
    description = str(row.get("description") or "").lower()
    if any(token in description for token in SWAP_DESCRIPTIONS):
        return False
    if "reserved" in description or "metadata" in description:
        return False
    return any(
        token in description
        for token in ("fat", "exfat", "ntfs", "basic data", "efi system", "msdos", "ext", "linux", "xfs", "hfs", "apfs", "ufs")
    )


def select_native_partition(
    partitions: list[dict[str, object]],
    *,
    preferred_start_sector: int | None = None,
) -> int | None:
    """Pick a filesystem partition, honoring an explicit start sector."""
    if preferred_start_sector is not None:
        for row in partitions:
            if int(row.get("start_sector") or -1) == preferred_start_sector:
                if not _is_supported_partition(row):
                    record_coverage("e01_native.partition", "partition_not_supported", None, None, "partition")
                    raise ValueError(
                        f"requested partition start sector {preferred_start_sector} does not look like a supported filesystem"
                    )
                return preferred_start_sector
        raise ValueError(f"requested partition start sector {preferred_start_sector} was not found in the partition table")
    best_start = None
    best_size = -1
    for row in partitions:
        if not _is_supported_partition(row):
            continue
        count = int(row.get("sector_count") or 0)
        if count > best_size:
            best_size = count
            best_start = int(row.get("start_sector") or 0)
    return best_start


_INVALID_NAME_CHARS = '<>:"/\\|?*'


def _safe_component(name: str) -> str:
    cleaned = "".join("_" if ch in _INVALID_NAME_CHARS or ord(ch) < 0x20 else ch for ch in name)
    cleaned = cleaned.rstrip(" .") or "_"
    return cleaned[:180]


def _record_sequence(rec: Any) -> int:
    index = rec.index() if callable(getattr(rec, "index", None)) else getattr(rec, "index", 0)
    return int(index or 0)


def _dump_ntfs_record(rec: Any, out_path: Path, stats: dict[str, int]) -> None:
    try:
        size = int(rec.size())
    except Exception:
        stats["errors"] += 1
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        src = rec.open()
    except Exception:
        stats["errors"] += 1
        return
    remaining = size
    try:
        with out_path.open("wb") as dst:
            while remaining > 0:
                chunk = src.read(min(8 << 20, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)
    except Exception:
        stats["errors"] += 1
        try:
            out_path.unlink(missing_ok=True)
        except OSError:
            pass
        return
    stats["files"] += 1
    stats["bytes"] += size - max(remaining, 0)


@dataclass(frozen=True)
class _ExtractJob:
    segment: int
    out_path: Path
    deleted: bool = False
    # recovery mode: keep the readable bytes of a damaged deleted record and flag it partial
    salvage: bool = False
    reallocated: bool = False


# NTFS $FILE_NAME namespace of a DOS 8.3-only name (dissect.ntfs.c_ntfs.FILE_NAME_DOS).
_FILE_NAME_DOS = 2


def _is_dos_name_entry(entry: Any) -> bool:
    try:
        return int(entry.attribute.flags) == _FILE_NAME_DOS
    except Exception:
        return False


def _plan_ntfs_dir(node: Any, out_dir: Path, stats: dict[str, int], jobs: list[_ExtractJob], depth: int = 0, limit: int = 0) -> None:
    """Metadata-only twin of ``_walk_ntfs_dir``: collect file jobs instead of reading content."""
    if depth > 64:
        stats["depth_skips"] += 1
        return
    # Read the $I30 index once and follow each entry's MFT reference directly. Resolving every
    # name again with node.get(name) re-searched the index from this directory per entry, which
    # made planning a large volume take hours before the first byte was extracted.
    try:
        entries = list(node.iterdir())
    except Exception:
        stats["errors"] += 1
        return
    # Long names first; a DOS 8.3 alias only counts when its record has no long name.
    entries.sort(key=lambda entry: _is_dos_name_entry(entry))
    seen_segments: set[int] = set()
    for entry in entries:
        try:
            name = entry.attribute.file_name
        except Exception:
            stats["errors"] += 1
            continue
        if name in (".", ".."):
            continue
        try:
            rec = entry.dereference()
        except Exception:
            stats["errors"] += 1
            continue
        if rec is None:
            continue
        segment = getattr(rec, "segment", None)
        if segment is not None:
            if segment in seen_segments:
                stats["alias_skips"] += 1
                continue
            seen_segments.add(segment)
        target = out_dir / _safe_component(name)
        try:
            if rec.is_dir():
                _plan_ntfs_dir(rec, target, stats, jobs, depth + 1, limit)
            elif rec.is_file():
                if len(jobs) >= limit:
                    stats["truncated"] += 1
                    continue
                if segment is None:
                    stats["errors"] += 1
                    continue
                jobs.append(_ExtractJob(int(segment), target))
        except Exception:
            stats["errors"] += 1
            continue


def _volume_bitmap(fs: Any) -> bytes | None:
    """The NTFS ``$Bitmap`` (record 6) cluster-allocation bitmap, or ``None`` when unreadable."""
    try:
        rec = fs.mft.get(6)
        return bytes(rec.open().read(int(rec.size())))
    except Exception:
        return None


def _any_cluster_allocated(bitmap: bytes, start: int, count: int) -> bool:
    end = start + count
    if start < 0 or end > len(bitmap) * 8:
        return True  # run points outside the volume: its bytes cannot be the original content
    while start < end and start % 8:
        if bitmap[start >> 3] & (1 << (start & 7)):
            return True
        start += 1
    full_end = end - end % 8
    if start < full_end and any(bitmap[start >> 3 : full_end >> 3]):
        return True
    start = max(start, full_end)
    while start < end:
        if bitmap[start >> 3] & (1 << (start & 7)):
            return True
        start += 1
    return False


def _runs_reallocated(rec: Any, bitmap: bytes) -> bool:
    """True when any cluster of a deleted record's data runs is allocated again (to another file)."""
    try:
        runs = rec.dataruns()
    except Exception:  # resident data or no $DATA stream: nothing on disk to be reallocated
        return False
    return any(lcn is not None and _any_cluster_allocated(bitmap, int(lcn), int(count)) for lcn, count in runs)


def _plan_deleted_mft_records(
    fs: Any,
    extract_dir: Path,
    stats: dict[str, int],
    jobs: list[_ExtractJob],
    limit: int | None,
    *,
    recovery: bool = False,
) -> None:
    """Queue MFT records whose in-use flag is cleared under ``_deleted_mft/``.

    Recovery mode sweeps every record (no job cap, no consecutive-missing stop) and
    queues salvage jobs that keep partly unreadable or reallocated records flagged
    ``partial``. Outside recovery mode any cut is disclosed via ``record_coverage``.
    """
    total = _mft_record_count(fs)
    deleted_dir = extract_dir / "_deleted_mft"
    bitmap = _volume_bitmap(fs) if recovery else None
    consecutive_missing = 0
    capped = 0
    queued = 0
    for index in range(total):
        try:
            rec = fs.mft.get(index)
        except Exception:
            consecutive_missing += 1
            if not recovery and consecutive_missing > 100_000 and index > 16:
                record_coverage("e01_native.deleted_mft", "deleted-sweep-cap", total, index, "mft_records")
                break
            continue
        consecutive_missing = 0
        try:
            if not rec.is_file() or (int(rec.header.Flags) & 0x01):
                continue
            filename = rec.filename or f"record-{index}"
        except Exception:
            continue
        if limit is not None and len(jobs) >= limit:
            stats["truncated"] += 1
            capped += 1
            continue
        reallocated = bitmap is not None and _runs_reallocated(rec, bitmap)
        target = deleted_dir / f"{index}-{_safe_component(filename)}"
        jobs.append(_ExtractJob(index, target, deleted=True, salvage=recovery, reallocated=reallocated))
        queued += 1
    if capped:
        record_coverage("e01_native.deleted_mft", "deleted-sweep-cap", limit, queued + capped, "files")


def _dump_hashed(rec: Any, out_path: Path) -> tuple[int, dict[str, str]] | None:
    """Stream ``rec`` to ``out_path`` once, hashing the same bytes. ``None`` on a per-file read error."""
    try:
        size = int(rec.size())
        src = rec.open()
    except Exception:
        return None
    hashers = {name: hashlib.new(name) for name in DIGEST_ALGORITHMS}
    remaining = size
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out_path.open("wb") as dst:
            while remaining > 0:
                chunk = src.read(min(8 << 20, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
                remaining -= len(chunk)
    except Exception:
        with contextlib.suppress(OSError):
            out_path.unlink(missing_ok=True)
        return None
    return size - max(remaining, 0), {name: h.hexdigest() for name, h in hashers.items()}


def _dump_hashed_salvage(
    rec: Any, out_path: Path, *, reallocated: bool = False
) -> tuple[int, dict[str, str], dict[str, Any]] | None:
    """Recovery-mode dump of a deleted entry: keep the readable prefix instead of discarding it.

    Returns ``(bytes_written, digests, partial_info)``; ``partial_info`` is empty for an
    intact entry, else ``{"partial": True, "partial_reasons": [...], "expected_size_bytes": n}``.
    ``None`` only when the output file cannot be written.
    """
    reasons: list[str] = ["reallocated"] if reallocated else []
    try:
        expected: int | None = int(rec.size())
    except Exception:
        expected = None
    hashers = {name: hashlib.new(name) for name in DIGEST_ALGORITHMS}
    written = 0
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("wb") as dst:
            src = None
            if expected is not None:
                try:
                    src = rec.open()
                except Exception:
                    src = None
            if src is None:
                reasons.append("unreadable")
            while src is not None and expected is not None and written < expected:
                try:
                    chunk = src.read(min(8 << 20, expected - written))
                except Exception:
                    reasons.append("unreadable")
                    break
                if not chunk:
                    reasons.append("short-read")
                    break
                dst.write(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
                written += len(chunk)
    except OSError:
        with contextlib.suppress(OSError):
            out_path.unlink(missing_ok=True)
        return None
    hexes = {name: h.hexdigest() for name, h in hashers.items()}
    if not reasons:
        return written, hexes, {}
    return written, hexes, {"partial": True, "partial_reasons": reasons, "expected_size_bytes": expected}


def _record_deleted_outcome(
    outcome: tuple[int, dict[str, str], dict[str, Any]], stats: dict[str, int]
) -> dict[str, Any]:
    size, hexes, partial = outcome
    stats["files"] += 1
    stats["bytes"] += size
    stats["deleted_files"] += 1
    if partial:
        stats["deleted_partial"] += 1
    return {"size_bytes": size, **hexes, **partial}


class _WorkerContexts:
    """One pyewf handle + NTFS instance per worker thread (pyewf handles are not thread-safe)."""

    def __init__(self, segments: list[Path], byte_offset: int, size: int):
        self._segments = segments
        self._byte_offset = byte_offset
        self._size = size
        self._local = threading.local()
        self._handles: list[Any] = []
        self._lock = threading.Lock()

    def fs(self) -> Any:
        fs = getattr(self._local, "fs", None)
        if fs is None:
            handle = open_ewf_segments(self._segments)
            with self._lock:
                self._handles.append(handle)
            fs = NTFS(EwfSectorReader(handle, base=self._byte_offset, size=self._size))
            self._local.fs = fs
        return fs

    def close(self) -> None:
        for handle in self._handles:
            with contextlib.suppress(Exception):
                handle.close()


def _extract_job(contexts: _WorkerContexts, job: _ExtractJob) -> tuple[_ExtractJob, tuple[Any, ...] | None]:
    rec = contexts.fs().mft.get(job.segment)
    if job.salvage:
        return job, _dump_hashed_salvage(rec, job.out_path, reallocated=job.reallocated)
    return job, _dump_hashed(rec, job.out_path)


def _run_extract_jobs(
    contexts: _WorkerContexts,
    jobs: list[_ExtractJob],
    extract_dir: Path,
    stats: dict[str, int],
    workers: int,
) -> dict[str, dict[str, Any]]:
    """Run jobs on ``workers`` threads; per-file read errors count in ``stats``, anything else raises."""
    digests: dict[str, dict[str, Any]] = {}
    if not jobs:
        return digests
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs))), thread_name_prefix="e01-extract")
    try:
        futures = [pool.submit(_extract_job, contexts, job) for job in jobs]
        for future in futures:
            job, outcome = future.result()  # re-raises a worker exception: the run fails loudly
            if outcome is None:
                stats["errors"] += 1
                if job.deleted:
                    stats["deleted_read_errors"] += 1
                continue
            rel = job.out_path.relative_to(extract_dir).as_posix()
            if job.salvage:
                digests[rel] = _record_deleted_outcome(outcome, stats)
                continue
            size, hexes = outcome
            stats["files"] += 1
            stats["bytes"] += size
            if job.deleted:
                stats["deleted_files"] += 1
            digests[rel] = {"size_bytes": size, **hexes}
    except BaseException:
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return digests


def _walk_ntfs_dir(
    node: Any,
    out_dir: Path,
    stats: dict[str, int],
    depth: int = 0,
    limit: int | None = None,
) -> None:
    if depth > 64:
        stats["depth_skips"] += 1
        return
    if limit is None:
        limit = native_extract_file_limit()
    try:
        # NTFS indexes carry both the Win32 long name and any DOS 8.3 alias
        # for the same record. Walk non-DOS names first and dedupe on the
        # record segment so each file is extracted once under its long name,
        # while records that only have a DOS name are still recovered.
        preferred_names = list(node.listdir(ignore_dos=True))
        dos_only_names = [n for n in node.listdir() if n not in preferred_names]
    except Exception:
        stats["errors"] += 1
        return
    seen_segments: set[int] = set()
    for name in (*preferred_names, *dos_only_names):
        if name in (".", ".."):
            continue
        try:
            rec = node.get(name)
        except Exception:
            stats["errors"] += 1
            continue
        if rec is None:
            continue
        segment = getattr(rec, "segment", None)
        if segment is not None:
            if segment in seen_segments:
                stats["alias_skips"] += 1
                continue
            seen_segments.add(segment)
        target = out_dir / _safe_component(name)
        try:
            if rec.is_dir():
                _walk_ntfs_dir(rec, target, stats, depth + 1, limit)
            elif rec.is_file():
                if stats["files"] >= limit:
                    stats["truncated"] += 1
                    continue
                _dump_ntfs_record(rec, target, stats)
        except Exception:
            stats["errors"] += 1
            continue


def _mft_record_count(fs: Any) -> int:
    try:
        stream_size = int(fs.mft.fh.size)
    except Exception:
        return 0
    record_size = 1024
    try:
        clusters_per_record = int(fs.boot_sector.clusters_per_file_record)
        if clusters_per_record < 0:
            record_size = 1 << (-clusters_per_record)
        elif clusters_per_record > 0:
            record_size = clusters_per_record * int(fs.cluster_size)
    except (AttributeError, TypeError, ValueError):
        record_size = 1024
    return stream_size // max(record_size, 256)


def _sweep_deleted_mft_records(
    fs: Any,
    extract_dir: Path,
    stats: dict[str, int],
    limit: int | None = None,
) -> None:
    """Best-effort recovery of MFT records whose in-use flag is cleared."""
    if limit is None:
        limit = native_extract_file_limit()
    total = _mft_record_count(fs)
    deleted_dir = extract_dir / "_deleted_mft"
    consecutive_missing = 0
    for index in range(total):
        try:
            rec = fs.mft.get(index)
        except Exception:
            consecutive_missing += 1
            if consecutive_missing > 100_000 and index > 16:
                break
            continue
        consecutive_missing = 0
        try:
            if not rec.is_file() or (int(rec.header.Flags) & 0x01):
                continue
            filename = rec.filename or f"record-{index}"
        except Exception:
            continue
        if stats["files"] >= limit:
            stats["truncated"] += 1
            continue
        target = deleted_dir / f"{index}-{_safe_component(filename)}"
        before_errors = stats["errors"]
        _dump_ntfs_record(rec, target, stats)
        if stats["errors"] != before_errors:
            stats["deleted_read_errors"] += 1
        else:
            stats["deleted_files"] += 1


def _dump_ntfs_system_record(rec: Any, out_path: Path) -> int:
    """Dump a raw NTFS record stream (e.g. $MFT) for reference-diff tooling."""
    size = int(rec.size())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    src = rec.open()
    remaining = size
    with out_path.open("wb") as dst:
        while remaining > 0:
            chunk = src.read(min(8 << 20, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
    return size - max(remaining, 0)


def _probe_filesystem(reader: EwfSectorReader) -> str | None:
    """Identify a partition's filesystem from its first sectors: ntfs, exfat, fat, ext or ``None``."""
    reader.seek(0)
    head = reader.read(2048)
    if head[3:11] == b"NTFS    ":
        return "ntfs"
    if head[3:11] == b"EXFAT   ":
        return "exfat"
    if len(head) >= 512 and head[510:512] == b"\x55\xaa" and (head[54:57] == b"FAT" or head[82:85] == b"FAT"):
        return "fat"
    if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
        return "ext"
    return None


def _tsk_available() -> bool:
    try:
        import pytsk3  # noqa: F401
    except ImportError:
        return False
    return True


class _TskStream:
    """Sequential ``read(n)`` over a pytsk3 file via ``read_random``."""

    def __init__(self, tsk_file: Any, size: int):
        self._file = tsk_file
        self._size = size
        self._pos = 0

    def read(self, n: int) -> bytes:
        n = min(n, self._size - self._pos)
        if n <= 0:
            return b""
        data = self._file.read_random(self._pos, n)
        self._pos += len(data)
        return data


class _TskFile:
    """Adapter giving a pytsk3 file the ``size()``/``open()`` shape ``_dump_hashed`` expects."""

    def __init__(self, tsk_file: Any):
        self._file = tsk_file
        self._size = int(tsk_file.info.meta.size)

    def size(self) -> int:
        return self._size

    def open(self) -> _TskStream:
        return _TskStream(self._file, self._size)


def _walk_tsk_dir(
    directory: Any,
    out_dir: Path,
    root_dir: Path,
    stats: dict[str, int],
    digests: dict[str, dict[str, Any]],
    limit: int,
    depth: int = 0,
    *,
    recovery: bool = False,
    in_deleted: bool = False,
) -> None:
    """Walk a pytsk3 directory. Recovery mode also writes unallocated entries under ``_deleted/``
    (``<meta addr>-<name>``, uncapped, flagged ``partial`` when unreadable); otherwise they are
    counted in ``deleted_skipped``."""
    import pytsk3

    if depth > 64:
        stats["depth_skips"] += 1
        return
    try:
        entries = list(directory)
    except Exception:
        stats["errors"] += 1
        return
    for entry in entries:
        try:
            info = entry.info
            meta = info.meta
            raw_name = info.name.name if info.name is not None else None
            if meta is None or raw_name is None:
                continue
            name = raw_name.decode("utf-8", "replace")
            if name in (".", ".."):
                continue
            unalloc = bool(int(info.name.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC) or bool(
                int(meta.flags) & pytsk3.TSK_FS_META_FLAG_UNALLOC
            )
            deleted = in_deleted or unalloc
            if deleted and not recovery:
                if meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                    stats["deleted_skipped"] += 1
                continue
            if deleted:
                parent = out_dir if in_deleted else root_dir / "_deleted" / out_dir.relative_to(root_dir)
                target = parent / _safe_component(f"{int(meta.addr)}-{name}")
            else:
                target = out_dir / _safe_component(name)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                _walk_tsk_dir(
                    entry.as_directory(), target, root_dir, stats, digests, limit, depth + 1,
                    recovery=recovery, in_deleted=deleted,
                )
            elif meta.type == pytsk3.TSK_FS_META_TYPE_REG and deleted:
                salvaged = _dump_hashed_salvage(_TskFile(entry), target)
                if salvaged is None:
                    stats["errors"] += 1
                    stats["deleted_read_errors"] += 1
                    continue
                digests[target.relative_to(root_dir).as_posix()] = _record_deleted_outcome(salvaged, stats)
            elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                if stats["files"] - stats["deleted_files"] >= limit:  # the cap covers allocated files only
                    stats["truncated"] += 1
                    continue
                outcome = _dump_hashed(_TskFile(entry), target)
                if outcome is None:
                    stats["errors"] += 1
                    continue
                size, hexes = outcome
                stats["files"] += 1
                stats["bytes"] += size
                digests[target.relative_to(root_dir).as_posix()] = {"size_bytes": size, **hexes}
        except Exception:
            stats["errors"] += 1
            continue


class _TskOpenError(Exception):
    """pytsk3 could not open the partition as a filesystem."""


def _extract_tsk_partition(
    handle: Any,
    byte_offset: int,
    part_dir: Path,
    stats: dict[str, int],
    limit: int,
    *,
    recovery: bool = False,
    include_deleted: bool = True,
) -> dict[str, dict[str, Any]]:
    """Recursive file walk of a FAT/exFAT/ext partition through pytsk3 over the pyewf handle.

    Allocated files always; deleted (unallocated) entries only in recovery mode. Outside
    recovery mode skipped deleted files are disclosed as a ``deleted-sweep-cap`` coverage entry.
    """
    import pytsk3

    media_size = int(handle.get_media_size())

    class _EwfImg(pytsk3.Img_Info):
        def __init__(self) -> None:
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def get_size(self) -> int:
            return media_size

        def read(self, offset: int, length: int) -> bytes:
            handle.seek(offset)
            return handle.read(length)

    try:
        fs = pytsk3.FS_Info(_EwfImg(), offset=byte_offset)
    except OSError as exc:  # the signature probe matched but TSK cannot open the volume
        raise _TskOpenError(str(exc)) from exc
    digests: dict[str, dict[str, Any]] = {}
    sweep = recovery and include_deleted
    _walk_tsk_dir(fs.open_dir(path="/"), part_dir, part_dir, stats, digests, limit, recovery=sweep)
    if include_deleted and not sweep and stats["deleted_skipped"]:
        record_coverage("e01_native.deleted_tsk", "deleted-sweep-cap", 0, stats["deleted_skipped"], "files")
    return digests


def _new_stats() -> dict[str, int]:
    return {
        "files": 0,
        "bytes": 0,
        "errors": 0,
        "depth_skips": 0,
        "truncated": 0,
        "deleted_files": 0,
        "deleted_read_errors": 0,
        "deleted_partial": 0,
        "deleted_skipped": 0,
        "alias_skips": 0,
    }


def _extract_ntfs_partition(
    handle: Any,
    segments: list[Path],
    row: dict[str, object],
    part_dir: Path,
    stats: dict[str, int],
    limit: int,
    workers: int,
    include_deleted: bool,
    mft_path: Path | None,
    system_artifacts: dict[str, str],
    artifact_key: str,
    recovery: bool = False,
) -> tuple[dict[str, dict[str, Any]], Any]:
    byte_offset = int(row.get("byte_offset") or 0)
    size = int(row.get("size_bytes") or 0)
    fs = NTFS(EwfSectorReader(handle, base=byte_offset, size=size or None))
    root = fs.mft.get(5)
    jobs: list[_ExtractJob] = []
    _plan_ntfs_dir(root, part_dir, stats, jobs, limit=limit)
    if include_deleted:
        _plan_deleted_mft_records(fs, part_dir, stats, jobs, None if recovery else limit, recovery=recovery)
    contexts = _WorkerContexts(segments, byte_offset, size)
    try:
        digests = _run_extract_jobs(contexts, jobs, part_dir, stats, workers)
    finally:
        contexts.close()
    if mft_path is not None:
        # Dump $MFT (record 0) outside the recovered tree so reference-diff
        # tooling can compare the native view with ils/fls -rp output.
        try:
            _dump_ntfs_system_record(fs.mft.get(0), mft_path)
            system_artifacts[artifact_key] = str(mft_path)
            system_artifacts.setdefault("mft", str(mft_path))
        except Exception:
            stats["errors"] += 1
    return digests, fs


_NON_FILESYSTEM_TOKENS = ("swap", "reserved", "protective", "extended")


def extract_e01_native(
    source_path: Path,
    segments: list[Path],
    extract_dir: Path,
    *,
    partition_start_sector: int | None = None,
    include_deleted: bool = True,
    system_dir: Path | None = None,
    run_mode: str | None = None,
) -> dict[str, Any]:
    """Open an EWF segment set and recover files from every supported partition.

    ``run_mode="recovery"`` makes the deleted sweep unbounded (NTFS ``_deleted_mft/``,
    pytsk3 ``_deleted/``) and keeps damaged deleted entries flagged ``partial`` in
    ``file_digests``; other modes keep the bounded sweep.

    NTFS goes through dissect.ntfs; FAT/exFAT/ext through pytsk3. A single
    extracted partition keeps the flat layout (``extract_dir`` is the volume
    root); several land in ``extract_dir/p<index>/``. Partitions that cannot be
    read are recorded with ``record_coverage``. An explicit
    ``partition_start_sector`` extracts only that partition.

    Returns a result payload with partition table, selection, and extraction
    statistics; the caller is responsible for checkpoint provenance.
    """
    recovery = run_mode == "recovery"
    handle = open_ewf_segments(segments)
    try:
        partitions, sector_size = native_partition_table(handle)
        explicit = partition_start_sector is not None
        if explicit:
            start = select_native_partition(partitions, preferred_start_sector=partition_start_sector)
            candidates = [p for p in partitions if int(p.get("start_sector") or -1) == start]
        else:
            candidates = list(partitions)
        tsk_ok = _tsk_available()
        plan: list[tuple[dict[str, object], str]] = []
        skipped: list[dict[str, object]] = []
        for row in candidates:
            byte_offset = int(row.get("byte_offset") or int(row.get("start_sector") or 0) * sector_size)
            reader = EwfSectorReader(handle, base=byte_offset, size=int(row.get("size_bytes") or 0) or None)
            kind = _probe_filesystem(reader)
            row["native_filesystem"] = kind or "unknown"
            if kind == "ntfs" or (kind is not None and tsk_ok):
                plan.append((row, kind))
            else:
                skipped.append(row)
        multi = len(plan) > 1
        file_limit = native_extract_file_limit()
        workers = native_extract_worker_count()
        stats = {**_new_stats(), "file_limit": file_limit, "workers": workers}
        digests: dict[str, dict[str, Any]] = {}
        system_artifacts: dict[str, str] = {}
        extracted: list[dict[str, object]] = []
        primary: dict[str, object] | None = None
        primary_fs: Any = None
        for row, kind in sorted(plan, key=lambda item: int(item[0].get("partition_number") or 0)):
            number = int(row.get("partition_number") or 0)
            part_dir = extract_dir / f"p{number}" if multi else extract_dir
            part_stats = _new_stats()
            remaining = max(0, file_limit - stats["files"])
            fs_obj: Any = None
            if kind == "ntfs":
                mft_path = None
                if system_dir is not None:
                    mft_path = system_dir / (f"MFT-p{number}.bin" if multi else "MFT.bin")
                part_digests, fs_obj = _extract_ntfs_partition(
                    handle, segments, row, part_dir, part_stats, remaining, workers, include_deleted,
                    mft_path, system_artifacts, f"mft_p{number}", recovery,
                )
            else:
                try:
                    part_digests = _extract_tsk_partition(
                        handle, int(row.get("byte_offset") or 0), part_dir, part_stats, remaining,
                        recovery=recovery, include_deleted=include_deleted,
                    )
                except _TskOpenError:
                    row["native_filesystem"] = "unknown"
                    skipped.append(row)
                    continue
            prefix = f"p{number}/" if multi else ""
            digests.update({prefix + rel: entry for rel, entry in part_digests.items()})
            for key, value in part_stats.items():
                stats[key] += value
            row["native_extracted"] = True
            extracted.append(
                {
                    "start_sector": int(row.get("start_sector") or 0),
                    "partition_number": number,
                    "filesystem": kind,
                    "directory": f"p{number}" if multi else "",
                    "stats": part_stats,
                }
            )
            if primary is None or int(row.get("sector_count") or 0) > int(primary.get("sector_count") or 0):
                primary = row
                primary_fs = fs_obj
        if primary is None:
            start_sector = int(candidates[0].get("start_sector") or 0) if candidates else 0
            selected = candidates[0] if candidates else {}
            record_coverage("e01_native.filesystem", "unsupported_filesystem", None, None, "filesystem")
            readable = str(selected.get("native_filesystem") or "unknown")
            raise ValueError(
                f"native E01 extraction supports NTFS, FAT, exFAT and ext only; partition at sector {start_sector} "
                f"reports filesystem signature '{readable}' ({selected.get('description') or 'untyped'}). "
                "Mount or export the image with a trusted tool, then select the resulting folder."
            )
        for row in skipped:
            description = str(row.get("description") or "").lower()
            if any(token in description for token in _NON_FILESYSTEM_TOKENS):
                continue
            record_coverage("partition", "unsupported-filesystem", None, int(row.get("start_sector") or 0), "start_sector")
        return {
            "media_size_bytes": int(handle.get_media_size()),
            "sector_size_bytes": sector_size,
            "partition_table": partitions,
            "selected_partition": primary,
            "selected_start_sector": int(primary.get("start_sector") or 0),
            "extracted_partitions": extracted,
            "stats": stats,
            "system_artifacts": system_artifacts,
            "file_digests": digests,
            "volume_name": getattr(primary_fs, "volume_name", "") or "",
            "serial": getattr(primary_fs, "serial", None),
        }
    finally:
        with contextlib.suppress(Exception):
            handle.close()
