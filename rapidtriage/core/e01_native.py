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
import io
import struct
import uuid
from pathlib import Path
from typing import Any

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


def _walk_ntfs_dir(node: Any, out_dir: Path, stats: dict[str, int], depth: int = 0) -> None:
    if depth > 64:
        stats["depth_skips"] += 1
        return
    try:
        names = list(node.listdir())
    except Exception:
        stats["errors"] += 1
        return
    for name in names:
        if name in (".", ".."):
            continue
        try:
            rec = node.get(name)
        except Exception:
            stats["errors"] += 1
            continue
        if rec is None:
            continue
        target = out_dir / _safe_component(name)
        try:
            if rec.is_dir():
                _walk_ntfs_dir(rec, target, stats, depth + 1)
            elif rec.is_file():
                if stats["files"] >= MAX_NATIVE_EXTRACT_FILES:
                    stats["truncated"] += 1
                    return
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


def _sweep_deleted_mft_records(fs: Any, extract_dir: Path, stats: dict[str, int]) -> None:
    """Best-effort recovery of MFT records whose in-use flag is cleared."""
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
        target = deleted_dir / f"{index}-{_safe_component(filename)}"
        before_errors = stats["errors"]
        _dump_ntfs_record(rec, target, stats)
        if stats["errors"] != before_errors:
            stats["deleted_read_errors"] += 1
        else:
            stats["deleted_files"] += 1
        if stats["files"] >= MAX_NATIVE_EXTRACT_FILES:
            stats["truncated"] += 1
            return


def extract_e01_native(
    source_path: Path,
    segments: list[Path],
    extract_dir: Path,
    *,
    partition_start_sector: int | None = None,
    include_deleted: bool = True,
) -> dict[str, Any]:
    """Open an EWF segment set, select a partition, and recover files via NTFS.

    Returns a result payload with partition table, selection, and extraction
    statistics; the caller is responsible for checkpoint provenance.
    """
    handle = open_ewf_segments(segments)
    try:
        partitions, sector_size = native_partition_table(handle)
        start_sector = select_native_partition(partitions, preferred_start_sector=partition_start_sector)
        if start_sector is None:
            raise ValueError("no supported filesystem partition found in the native partition table")
        selected = next(p for p in partitions if int(p.get("start_sector") or -1) == start_sector)
        byte_offset = int(selected.get("byte_offset") or start_sector * sector_size)
        reader = EwfSectorReader(handle, base=byte_offset, size=int(selected.get("size_bytes") or 0))
        fs = NTFS(reader)
        stats: dict[str, int] = {
            "files": 0,
            "bytes": 0,
            "errors": 0,
            "depth_skips": 0,
            "truncated": 0,
            "deleted_files": 0,
            "deleted_read_errors": 0,
        }
        root = fs.mft.get(5)
        _walk_ntfs_dir(root, extract_dir, stats)
        if include_deleted:
            _sweep_deleted_mft_records(fs, extract_dir, stats)
        return {
            "media_size_bytes": int(handle.get_media_size()),
            "sector_size_bytes": sector_size,
            "partition_table": partitions,
            "selected_partition": selected,
            "selected_start_sector": start_sector,
            "stats": stats,
            "volume_name": getattr(fs, "volume_name", "") or "",
            "serial": getattr(fs, "serial", None),
        }
    finally:
        with contextlib.suppress(Exception):
            handle.close()
