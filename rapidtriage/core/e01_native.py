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
import importlib.metadata
import io
import itertools
import os
import shutil
import struct
import sys
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .e01_extract_engine import e01_extract_engine_status, run_rust_extraction

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
# File cap policy (allocated tree and deleted-record sweep each get the cap):
# the default is sized from the volume's $MFT record count, so a normal volume
# is recovered completely. A fixed 200k cap left most entries of a full Windows
# volume unrecovered, in directory-walk order (whatever came late in the walk
# was simply missing). MAX_NATIVE_EXTRACT_FILES is the floor
# (and the cap when the $MFT size cannot be read); NATIVE_EXTRACT_FILES_CEILING
# bounds a corrupt or absurd $MFT size. The real resource bound is disk space:
# extraction stops writing once the output drive would drop below
# RAPIDTRIAGE_NATIVE_MIN_FREE_GB (default 20 GB, left for the later stages).
# RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES still sets a fixed cap (quick triage).
MAX_NATIVE_EXTRACT_FILES = 200_000
NATIVE_EXTRACT_FILES_CEILING = 4_000_000
MAX_NATIVE_EXTRACT_BYTES = 0  # 0 = unbounded; callers may cap later
NATIVE_MAX_EXTRACT_FILES_ENV = "RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES"
NATIVE_MIN_FREE_GB_ENV = "RAPIDTRIAGE_NATIVE_MIN_FREE_GB"
DEFAULT_NATIVE_MIN_FREE_BYTES = 20 << 30
# Free space is re-read after this many files or bytes (and before any file the estimate cannot fit).
SPACE_CHECK_EVERY_FILES = 256
SPACE_CHECK_EVERY_BYTES = 1 << 30


def native_extract_file_limit_override() -> int | None:
    """The fixed cap set through ``RAPIDTRIAGE_NATIVE_MAX_EXTRACT_FILES`` (``None`` when unset/invalid)."""
    raw = os.environ.get(NATIVE_MAX_EXTRACT_FILES_ENV, "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return None


def native_extract_file_limit(mft_records: int = 0) -> int:
    """Active per-image extraction cap: the env override, else sized from the $MFT record count."""
    override = native_extract_file_limit_override()
    if override is not None:
        return override
    return min(NATIVE_EXTRACT_FILES_CEILING, max(MAX_NATIVE_EXTRACT_FILES, int(mft_records)))


def native_min_free_bytes() -> int:
    """Free space extraction leaves on the output drive (``RAPIDTRIAGE_NATIVE_MIN_FREE_GB``)."""
    raw = os.environ.get(NATIVE_MIN_FREE_GB_ENV, "").strip()
    if raw:
        try:
            value = float(raw)
            if value >= 0:
                return int(value * (1 << 30))
        except ValueError:
            pass
    return DEFAULT_NATIVE_MIN_FREE_BYTES


class ExtractSpaceGuard:
    """Stops native extraction from filling the output drive.

    ``allows(size)`` keeps a running free-space estimate (re-read every
    ``SPACE_CHECK_EVERY_FILES`` files / ``SPACE_CHECK_EVERY_BYTES`` bytes and
    before a file the estimate cannot fit). Once a file would leave less than
    ``reserve`` bytes free, nothing more is written (``tripped``).
    """

    def __init__(self, directory: Path, reserve: int) -> None:
        self.directory = directory
        self.reserve = reserve
        self.free = self._probe()
        self.free_at_start = self.free
        self.tripped = False
        self._files = 0
        self._bytes = 0

    def _probe(self) -> int:
        probe = self.directory
        while not probe.exists() and probe.parent != probe:
            probe = probe.parent
        try:
            return int(shutil.disk_usage(probe).free)
        except OSError:
            return -1  # unknown: the guard does not block

    def allows(self, size: int) -> bool:
        if self.tripped:
            return False
        if self.free < 0:
            return True  # free space unreadable at start: not guarded
        if self._files >= SPACE_CHECK_EVERY_FILES or self._bytes >= SPACE_CHECK_EVERY_BYTES or self.free - size < self.reserve:
            probed = self._probe()
            if probed >= 0:
                self.free = probed
            self._files = self._bytes = 0
        if self.free - size < self.reserve:
            self.tripped = True
            return False
        self._files += 1
        self._bytes += size
        self.free -= size
        return True


# pyproject `native-e01` extra: dissect.ntfs>=3.10.
NATIVE_NTFS_MIN_VERSION = (3, 10)


def _version_tuple(text: str | None) -> tuple[int, ...] | None:
    parts: list[int] = []
    for piece in (text or "").split("."):
        digits = "".join(itertools.takewhile(str.isdigit, piece))
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or None


def _distribution_version(name: str) -> str | None:
    """Installed version, or None for vendored/frozen builds without dist metadata."""
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def native_e01_status() -> dict[str, Any]:
    """Import + smoke check of the native-e01 extra, with the versions in use.

    ``problems`` is empty only when both modules import, a pyewf handle can be
    constructed (exercises the libewf binding) and dissect.ntfs is not older
    than the declared minimum; doctor, the evidence adapter and ``run`` gate on it.
    """
    problems: list[str] = []
    versions: dict[str, str | None] = {"pyewf": None, "dissect.ntfs": None}
    if pyewf is None:
        problems.append("pyewf is not importable")
    else:
        try:
            versions["pyewf"] = str(pyewf.get_version())
            pyewf.handle()
        except Exception as exc:
            problems.append(f"pyewf is importable but unusable ({type(exc).__name__}: {exc})")
    if NTFS is None:
        problems.append("dissect.ntfs is not importable")
    else:
        versions["dissect.ntfs"] = _distribution_version("dissect.ntfs")
        parsed = _version_tuple(versions["dissect.ntfs"])
        if parsed is not None and parsed < NATIVE_NTFS_MIN_VERSION:
            minimum = ".".join(map(str, NATIVE_NTFS_MIN_VERSION))
            problems.append(f"dissect.ntfs {versions['dissect.ntfs']} is older than the required {minimum}")
    return {"available": not problems, "versions": versions, "problems": problems}


def native_e01_available() -> bool:
    return bool(native_e01_status()["available"])


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
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", *(f"{port}{n}" for port in ("COM", "LPT") for n in "0123456789¹²³")}
)


def _is_windows_device_name(name: str) -> bool:
    """Win32 opens the device, not a file in the output folder, for ``CON``, ``nul.txt``,
    ``COM1 .log``, ... (the name before the first dot, trailing spaces ignored)."""
    return name.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_DEVICE_NAMES


def _safe_component(name: str) -> str:
    cleaned = "".join("_" if ch in _INVALID_NAME_CHARS or ord(ch) < 0x20 else ch for ch in name)
    cleaned = cleaned.rstrip(" .") or "_"
    if os.name == "nt" and _is_windows_device_name(cleaned):
        cleaned = "_" + cleaned
    return cleaned[:180]


def _record_sequence(rec: Any) -> int:
    index = rec.index() if callable(getattr(rec, "index", None)) else getattr(rec, "index", 0)
    return int(index or 0)


# Output tree names (``_OutputNames``). Each recovered file or directory is one (output directory,
# MFT record) pair; when its name is taken (two records whose names _safe_component makes equal,
# or that the output drive folds together: case, Unicode normalization, 8.3 aliases), the later
# record in walk order gets a tagged name instead of overwriting or merging into the first.
DELETED_SWEEP_DIR = "_deleted_mft"
# Names one record tries (the plain name, then tagged ones) before it is reported unresolved.
_OUTPUT_NAME_ATTEMPTS = 32
# Entries kept in ``output_name_collisions``; the stats count every collision.
OUTPUT_NAME_COLLISION_REPORT_LIMIT = 1000
_O_BINARY = getattr(os, "O_BINARY", 0)


def _tagged_name(base: str, segment: int | None, attempt: int) -> str:
    """``base``, then ``<stem>~mft<segment>[-<attempt>]<extension>`` within 180 characters; the
    extension (up to 16 characters) is kept so parsers that select files by suffix still see it."""
    if attempt == 0:
        return base
    tag = f"~mft{'' if segment is None else segment}" + (f"-{attempt}" if attempt > 1 else "")
    dot = base.rfind(".")
    extension = base[dot:] if 0 < dot and len(base) - dot <= 16 else ""
    stem = base[: len(base) - len(extension)]
    return stem[: max(1, 180 - len(tag) - len(extension))] + tag + extension


def _file_identity(status: os.stat_result) -> tuple[int, int] | None:
    """The output drive's identity of a file or directory; None where the drive reports none."""
    return (status.st_dev, status.st_ino) if status.st_ino else None


class _OutputEntry:
    """One recovered file or directory: the source record it stands for and, once written, its path."""

    __slots__ = ("base", "children", "identity", "names", "parent", "path", "segment", "sequence", "source_name", "source_path")

    def __init__(
        self,
        names: _OutputNames,
        parent: _OutputEntry | None,
        base: str,
        rec: Any,
        source_name: str,
        source_path: str | None,
    ) -> None:
        self.names = names
        self.parent = parent
        self.base = base
        self.segment: int | None = getattr(rec, "segment", None)
        try:
            self.sequence: int | None = int(rec.header.SequenceNumber)
        except (AttributeError, TypeError, ValueError):
            self.sequence = None
        self.source_name = source_name
        self.source_path = source_path
        self.path: Path | None = None
        self.identity: tuple[int, int] | None = None
        self.children: dict[object, _OutputEntry] = {}

    def child(self, base: str, rec: Any, source_name: str) -> _OutputEntry:
        """The entry of ``rec`` below this directory: one per MFT record, whatever name reached it
        (a record without a segment number, which dissect always sets, by its output name)."""
        segment = getattr(rec, "segment", None)
        key: object = segment if segment is not None else ("name", base)
        found = self.children.get(key)
        if found is None:
            source_path = None if self.source_path is None else "/".join(filter(None, (self.source_path, source_name)))
            found = self.children[key] = _OutputEntry(self.names, self, base, rec, source_name, source_path)
        return found


class _OutputNames:
    """Gives every recovered record its own output file or directory (see ``_tagged_name``).

    A name is taken when another record was given the same path in this run, or when the drive
    resolves the path to a file or directory written for another record (checked before writing;
    the drive decides what it folds). Renamed records are listed in ``report`` with their source
    path and MFT identity; one that runs out of names is reported ``unresolved`` and not written.
    """

    def __init__(self, root: Path, stats: dict[str, int], *, reserve_deleted_dir: bool = False) -> None:
        self.stats = stats
        self.root = _OutputEntry(self, None, "", None, "", "")
        self.root.path = root
        self._root_made = False
        self._paths: dict[str, _OutputEntry] = {}
        self._live: dict[tuple[int, int], _OutputEntry] = {}
        self.report: list[dict[str, object]] = []
        # The deleted-record sweep folder; its records have no source directory.
        self.deleted_dir = _OutputEntry(self, self.root, DELETED_SWEEP_DIR, None, DELETED_SWEEP_DIR, None)
        if reserve_deleted_dir:
            self._paths[os.fspath(root / DELETED_SWEEP_DIR)] = self.deleted_dir

    def _taken(self, path: Path, entry: _OutputEntry) -> bool:
        if self._paths.setdefault(os.fspath(path), entry) is not entry:
            return True
        try:
            identity = _file_identity(os.lstat(path))
        except OSError:
            return False
        return identity is not None and self._live.get(identity, entry) is not entry

    def _claim(self, entry: _OutputEntry, path: Path, identity: tuple[int, int] | None, kind: str, attempt: int) -> bool:
        if identity is not None and self._live.get(identity, entry) is not entry:
            return False
        if identity is not None:
            self._live[identity] = entry
        entry.path, entry.identity = path, identity
        if attempt:
            self.stats["name_collision_renames"] = self.stats.get("name_collision_renames", 0) + 1
            self._record(entry, kind, "renamed", path)
        return True

    def _record(self, entry: _OutputEntry, kind: str, status: str, path: Path | None) -> None:
        if len(self.report) < OUTPUT_NAME_COLLISION_REPORT_LIMIT:
            root = self.root.path
            assert root is not None
            self.report.append(
                {
                    "status": status,
                    "kind": kind,
                    "output_path": None if path is None else path.relative_to(root).as_posix(),
                    "source_name": entry.source_name,
                    "source_path": entry.source_path,
                    "mft_segment": entry.segment,
                    "mft_sequence": entry.sequence,
                }
            )

    def unresolved(self, entry: _OutputEntry) -> None:
        """``entry`` (a file) was not written: no name was left for it or for its directory."""
        self.stats["name_collisions_unresolved"] = self.stats.get("name_collisions_unresolved", 0) + 1
        self._record(entry, "file", "unresolved", None)

    def directory(self, entry: _OutputEntry) -> Path | None:
        """``entry``'s output directory, created with its parents; None when no name is left."""
        if entry.parent is None:
            assert entry.path is not None
            if not self._root_made:
                entry.path.mkdir(parents=True, exist_ok=True)
                self._root_made = True
            return entry.path
        if entry.path is not None:
            return entry.path
        parent = self.directory(entry.parent)
        if parent is None:
            return None
        for attempt in range(_OUTPUT_NAME_ATTEMPTS):
            path = parent / _tagged_name(entry.base, entry.segment, attempt)
            if self._taken(path, entry):
                continue
            path.mkdir(exist_ok=True)  # a file in the folder before the run raises (counted by the caller)
            if self._claim(entry, path, _file_identity(os.stat(path)), "directory", attempt):
                return path
        return None

    def create_file(self, entry: _OutputEntry, parent: Path) -> int | None:
        """Open ``entry``'s output file in ``parent`` for writing (``entry.path``); None when no
        name is left. An ``OSError`` leaves ``entry.path`` at the name that could not be opened."""
        for attempt in range(_OUTPUT_NAME_ATTEMPTS):
            path = parent / _tagged_name(entry.base, entry.segment, attempt)
            if self._taken(path, entry):
                continue
            entry.path = path
            # Not truncated before the check: the path may reach another record's file.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | _O_BINARY, 0o666)
            try:
                claimed = self._claim(entry, path, _file_identity(os.fstat(fd)), "file", attempt)
                if claimed:
                    os.ftruncate(fd, 0)
                    return fd
            except BaseException:
                os.close(fd)
                raise
            os.close(fd)
        return None

    def discard(self, entry: _OutputEntry) -> None:
        """Remove ``entry``'s file after a failed copy; its name stays taken."""
        if entry.identity is not None:
            self._live.pop(entry.identity, None)
            entry.identity = None
        if entry.path is not None:
            with contextlib.suppress(OSError):
                entry.path.unlink(missing_ok=True)


def _dump_ntfs_record(rec: Any, entry: _OutputEntry, stats: dict[str, int], guard: ExtractSpaceGuard | None = None) -> None:
    try:
        size = int(rec.size())
    except Exception:
        stats["errors"] += 1
        return
    if guard is not None and not guard.allows(size):
        stats["disk_space_skips"] += 1
        return
    assert entry.parent is not None
    names = entry.names
    parent = names.directory(entry.parent)
    if parent is None:
        names.unresolved(entry)
        stats["errors"] += 1
        return
    try:
        src = rec.open()
    except Exception:
        stats["errors"] += 1
        return
    remaining = size
    try:
        fd = names.create_file(entry, parent)
        if fd is None:
            names.unresolved(entry)
            stats["errors"] += 1
            return
        with os.fdopen(fd, "wb") as dst:
            while remaining > 0:
                chunk = src.read(min(8 << 20, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)
    except Exception:
        stats["errors"] += 1
        names.discard(entry)
        return
    stats["files"] += 1
    stats["bytes"] += size - max(remaining, 0)


ExtractProgress = Callable[[Mapping[str, int]], None]
"""Called after each recovered file with the running stats (files, bytes, errors, …)."""


def _notify_progress(on_progress: ExtractProgress | None, stats: dict[str, int]) -> None:
    """Hand the observer a read-only view; progress is advisory, so an observer that
    raises must neither abort recovery nor be counted as an unreadable file."""
    if on_progress is None:
        return
    with contextlib.suppress(Exception):
        on_progress(MappingProxyType(stats))


# $FILE_NAME namespace of a DOS 8.3 name (dissect.ntfs.c_ntfs.FILE_NAME_DOS).
_FILE_NAME_DOS = 0x02
_IndexEntries = list[tuple[str, Any]]


def _directory_entries(node: Any) -> tuple[_IndexEntries, _IndexEntries]:
    """``node``'s $I30 entries as (name, index entry), in index order: Win32 and POSIX names, then
    DOS 8.3 names.

    Callers follow each entry's own MFT reference (``IndexEntry.dereference``), never a lookup by
    name: NTFS looks names up case-insensitively, so of two entries whose names differ only in case
    (POSIX namespace, case-sensitive directories), each a record of its own, a lookup reaches one.
    """
    preferred: _IndexEntries = []
    dos: _IndexEntries = []
    for entry in node.iterdir():
        name = entry.attribute
        (dos if name.flags == _FILE_NAME_DOS else preferred).append((name.file_name, entry))
    return preferred, dos


def _walk_ntfs_dir(
    node: Any,
    out_dir: _OutputEntry,
    stats: dict[str, int],
    depth: int = 0,
    limit: int | None = None,
    on_progress: ExtractProgress | None = None,
    done: set[int] | None = None,
    guard: ExtractSpaceGuard | None = None,
    record_done: bool = False,
) -> None:
    # ``done``: MFT segments the priority pass recovered; the full walk skips them. Only the
    # priority pass records into it (``record_done``): recording every file of the full walk
    # would hold one entry per file of the volume and silently drop the other paths of a
    # hard-linked file (WinSxS / System32), which the walk has always recovered at each path.
    if depth > 64:
        stats["depth_skips"] += 1
        return
    if limit is None:
        limit = native_extract_file_limit()
    try:
        # NTFS indexes carry both the Win32 long name and any DOS 8.3 alias for the same record.
        # Walk non-DOS entries first and dedupe on the record segment, so each record is
        # extracted once under its long name (the alias counted in alias_skips), while records
        # that only have a DOS name are still recovered.
        preferred, dos = _directory_entries(node)
    except Exception:
        stats["errors"] += 1
        return
    seen_segments: set[int] = set()
    for name, entry in (*preferred, *dos):
        if name in (".", ".."):
            continue
        try:
            rec = entry.dereference()
        except Exception:
            stats["errors"] += 1
            continue
        segment = getattr(rec, "segment", None)
        if segment is not None:
            if segment in seen_segments:
                stats["alias_skips"] += 1
                continue
            seen_segments.add(segment)
        target = out_dir.child(_safe_component(name), rec, name)
        try:
            if rec.is_dir():
                _walk_ntfs_dir(rec, target, stats, depth + 1, limit, on_progress, done, guard, record_done)
            elif rec.is_file():
                if done is not None and segment is not None and segment in done:
                    continue  # already recovered by the priority pass
                if stats["files"] >= limit:
                    stats["truncated"] += 1
                    _notify_progress(on_progress, stats)  # the walk past the cap still takes minutes on a full volume
                    continue
                _dump_ntfs_record(rec, target, stats, guard)
                if record_done and done is not None and segment is not None:
                    done.add(segment)
                _notify_progress(on_progress, stats)
        except Exception:
            stats["errors"] += 1
            continue


# Forensic sources recovered before the full tree walk, so the file cap is never spent on
# Program Files / ProgramData first: the walk follows directory order, and on a full Windows
# volume the cap ran out in Users\ before Windows\ (no hives, event logs or Prefetch at all).
# "*" expands to every child directory (one per user profile).
PRIORITY_RECOVERY_PATHS: tuple[str, ...] = (
    "Windows/System32/config",
    "Windows/System32/winevt/Logs",
    "Windows/Prefetch",
    "Windows/appcompat/Programs",
    "Windows/System32/sru",
    "Windows/System32/Tasks",
    "Windows/inf/setupapi.dev.log",
    "Users/*/NTUSER.DAT",
    "Users/*/NTUSER.DAT.LOG1",
    "Users/*/NTUSER.DAT.LOG2",
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Users/*/AppData/Roaming/Microsoft/Windows/Recent",
    "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine",
    "$Recycle.Bin",
)


def _priority_targets(root: Any, pattern: str) -> list[tuple[tuple[str, Any], ...]]:
    """The (name, record) chains below ``root`` for one PRIORITY_RECOVERY_PATHS entry; missing
    parts yield none. A named part is looked up case-insensitively, as Windows resolves it; "*"
    follows every Win32/POSIX entry by its MFT reference (see ``_directory_entries``)."""
    found: list[tuple[tuple[str, Any], ...]] = [()]
    for part in pattern.split("/"):
        nxt: list[tuple[tuple[str, Any], ...]] = []
        for chain in found:
            node = chain[-1][1] if chain else root
            try:
                if part == "*":
                    children = [(name, entry) for name, entry in _directory_entries(node)[0] if name not in (".", "..")]
                else:
                    children = [(part, None)]
            except Exception:
                continue
            for name, entry in children:
                try:
                    child = node.get(name) if entry is None else entry.dereference()
                except Exception:
                    continue
                if child is None or (part == "*" and not child.is_dir()):
                    continue
                nxt.append((*chain, (name, child)))
        found = nxt
    return found


def _recover_priority_paths(
    root: Any,
    extract_dir: _OutputEntry,
    stats: dict[str, int],
    *,
    done: set[int],
    on_progress: ExtractProgress | None = None,
    guard: ExtractSpaceGuard | None = None,
) -> None:
    """Recover PRIORITY_RECOVERY_PATHS first, at the same relative paths the full walk uses.

    These forensic sources are exempt from the file cap (they count toward it, so the
    tree walk that follows gets what is left); only the disk-space guard stops them.
    """
    for pattern in PRIORITY_RECOVERY_PATHS:
        for chain in _priority_targets(root, pattern):
            target = extract_dir
            for name, node in chain:
                target = target.child(_safe_component(name), node, name)
            rec = chain[-1][1]
            try:
                if rec.is_dir():
                    _walk_ntfs_dir(
                        rec, target, stats, limit=sys.maxsize, on_progress=on_progress, done=done, guard=guard, record_done=True
                    )
                elif rec.is_file():
                    segment = getattr(rec, "segment", None)
                    if segment is not None and segment in done:
                        continue
                    _dump_ntfs_record(rec, target, stats, guard)
                    if segment is not None:
                        done.add(segment)
                    _notify_progress(on_progress, stats)
            except Exception:
                stats["errors"] += 1


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
    deleted_dir: _OutputEntry,
    stats: dict[str, int],
    limit: int | None = None,
    on_progress: ExtractProgress | None = None,
    guard: ExtractSpaceGuard | None = None,
) -> None:
    """Best-effort recovery of MFT records whose in-use flag is cleared, into ``deleted_dir``
    (``_OutputNames.deleted_dir``) as ``<record>-<name>``."""
    if limit is None:
        limit = native_extract_file_limit()
    total = _mft_record_count(fs)
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
        # Deleted records get their own budget: the sweep runs after the allocated walk, so a
        # shared cap (reached by the live tree on any full Windows volume) recovered none of them.
        if stats["deleted_files"] + stats["deleted_read_errors"] >= limit:
            stats["truncated"] += 1
            _notify_progress(on_progress, stats)
            continue
        target = deleted_dir.child(f"{index}-{_safe_component(filename)}", rec, filename)
        before_files, before_errors = stats["files"], stats["errors"]
        _dump_ntfs_record(rec, target, stats, guard)
        if stats["files"] != before_files:
            stats["deleted_files"] += 1
        elif stats["errors"] != before_errors:
            stats["deleted_read_errors"] += 1
        _notify_progress(on_progress, stats)


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


def extract_e01_native(
    source_path: Path,
    segments: list[Path],
    extract_dir: Path,
    *,
    partition_start_sector: int | None = None,
    include_deleted: bool = True,
    system_dir: Path | None = None,
    on_progress: ExtractProgress | None = None,
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
        partition_size = int(selected.get("size_bytes") or 0)
        reader = EwfSectorReader(handle, base=byte_offset, size=partition_size)
        reader.seek(0)
        boot = reader.read(512) or b""
        oem = boot[3:11]
        if oem != b"NTFS    ":
            readable = oem.decode("ascii", "replace").strip() or "unknown"
            raise ValueError(
                f"native E01 extraction supports NTFS only; partition at sector {start_sector} "
                f"reports filesystem signature '{readable}' ({selected.get('description') or 'untyped'}). "
                "Mount or export the image with a trusted tool, then select the resulting folder."
            )
        fs = NTFS(reader)
        mft_records = _mft_record_count(fs)
        guard = ExtractSpaceGuard(extract_dir, native_min_free_bytes())
        stats: dict[str, int] = {
            "files": 0,
            "bytes": 0,
            "errors": 0,
            "depth_skips": 0,
            "truncated": 0,
            "deleted_files": 0,
            "deleted_read_errors": 0,
            "alias_skips": 0,
            "name_collision_renames": 0,
            "name_collisions_unresolved": 0,
            "disk_space_skips": 0,
            "file_limit": native_extract_file_limit(mft_records),
            "file_limit_from_env": int(native_extract_file_limit_override() is not None),
            "mft_record_count": mft_records,
            "min_free_bytes": guard.reserve,
            "free_bytes_at_start": guard.free_at_start,
        }
        extract_engine = e01_extract_engine_status()
        collisions: list[dict[str, object]] = []
        if not (
            extract_engine["active"] == "rust"
            and run_rust_extraction(
                extract_engine,
                handle=handle,
                segments=segments,
                byte_offset=byte_offset,
                size=partition_size,
                extract_dir=extract_dir,
                stats=stats,
                collisions=collisions,
                include_deleted=include_deleted,
                priority_paths=PRIORITY_RECOVERY_PATHS,
                on_progress=on_progress,
                free_at_start=guard.free_at_start,
                min_free_bytes=guard.reserve,
                free_space_probe=guard._probe,
            )
        ):
            root = fs.mft.get(5)
            done: set[int] = set()
            names = _OutputNames(extract_dir, stats, reserve_deleted_dir=include_deleted)
            _recover_priority_paths(root, names.root, stats, done=done, on_progress=on_progress, guard=guard)
            _walk_ntfs_dir(
                root, names.root, stats, limit=stats["file_limit"], on_progress=on_progress, done=done, guard=guard
            )
            if include_deleted:
                _sweep_deleted_mft_records(
                    fs, names.deleted_dir, stats, limit=stats["file_limit"], on_progress=on_progress, guard=guard
                )
            collisions = names.report
        system_artifacts: dict[str, str] = {}
        if system_dir is not None:
            # Dump $MFT (record 0) outside the recovered tree so reference-diff
            # tooling can compare the native view with ils/fls -rp output.
            try:
                mft_rec = fs.mft.get(0)
                mft_path = system_dir / "MFT.bin"
                _dump_ntfs_system_record(mft_rec, mft_path)
                system_artifacts["mft"] = str(mft_path)
            except Exception:
                stats["errors"] += 1
        engine_fields = {"extract_engine": extract_engine} if extract_engine["requested"] != "python" else {}
        return {
            **engine_fields,
            "media_size_bytes": int(handle.get_media_size()),
            "sector_size_bytes": sector_size,
            "partition_table": partitions,
            "selected_partition": selected,
            "selected_start_sector": start_sector,
            "stats": stats,
            # Records written under another name than their own (or not at all) because the name
            # was taken: source path and MFT identity per entry (first 1,000; stats count all).
            "output_name_collisions": collisions,
            "system_artifacts": system_artifacts,
            "volume_name": getattr(fs, "volume_name", "") or "",
            "serial": getattr(fs, "serial", None),
        }
    finally:
        with contextlib.suppress(Exception):
            handle.close()
