"""Read-only access to one member of a ZIP the run already knows (``archive.zip::entry``).

Entry bytes are streamed from the original archive through :mod:`zipfile`; nothing is extracted
to disk and the archive is only ever opened for reading. The guards run before a byte is served:
the entry name must match a member exactly, directories, encrypted members and nested archive
paths are refused, and the declared size and compression ratio are capped (zip-bomb guard).
"""

from __future__ import annotations

import contextlib
import hashlib
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .source_reader import ARCHIVED_SOURCE_SEPARATOR, zip_info_modified_at

# Largest member served as bytes (the console renders PDFs up to the same size inline).
ARCHIVE_ENTRY_MAX_BYTES = 256 * 1024 * 1024
# Uncompressed/compressed ratio above which a member is treated as a zip bomb ...
ARCHIVE_ENTRY_MAX_RATIO = 100
# ... once it is large enough to matter: small members compress well without being a threat.
ARCHIVE_ENTRY_RATIO_FLOOR_BYTES = 1024 * 1024
ARCHIVE_LIST_MAX_ENTRIES = 1000
NESTED_ARCHIVE_SUFFIXES = frozenset({".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".egg", ".alz", ".jar"})

MISSING_ENTRY_MESSAGE = "압축 파일 안에 해당 항목이 없습니다"
DIRECTORY_ENTRY_MESSAGE = "압축 파일 안의 폴더입니다. 폴더 안의 파일을 선택하세요"
ENCRYPTED_ENTRY_MESSAGE = "암호화된 ZIP 항목은 열 수 없습니다(암호 해제는 지원하지 않습니다)"
NESTED_ENTRY_MESSAGE = "압축 파일 안의 압축 파일은 한 단계까지만 엽니다. 안쪽 압축 파일의 항목은 열 수 없습니다"
UNSAFE_NAME_MESSAGE = "상위 경로(..)나 절대 경로가 들어 있는 항목 이름이라 열지 않습니다"
INVALID_ARCHIVE_MESSAGE = "ZIP 형식으로 읽을 수 없는 파일입니다"


class ArchiveEntryError(ValueError):
    """An entry request the server refuses; ``status`` is the HTTP status it answers with."""

    def __init__(self, message: str, *, status: int) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """One regular, unencrypted member of ``archive_path`` that passed every guard."""

    archive_path: Path
    entry_name: str
    size: int
    compressed_size: int
    modified_at: str

    @property
    def entry_path(self) -> Path:
        return Path(self.entry_name)

    @property
    def name(self) -> str:
        return PurePosixPath(self.entry_name).name

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.entry_name).suffix

    def __str__(self) -> str:
        return f"{self.archive_path}{ARCHIVED_SOURCE_SEPARATOR}{self.entry_name}"


SourceFile = Path | ArchiveEntry


def is_unsafe_entry_name(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return path.is_absolute() or ".." in path.parts or ":" in (path.parts[0] if path.parts else "")


def compression_ratio(info: zipfile.ZipInfo) -> float:
    return info.file_size / max(info.compress_size, 1)


def refusal_reason(info: zipfile.ZipInfo) -> str | None:
    """Why ``info`` is not served as bytes, or ``None`` when it may be."""
    if info.is_dir():
        return DIRECTORY_ENTRY_MESSAGE
    if info.flag_bits & 0x1:
        return ENCRYPTED_ENTRY_MESSAGE
    if is_unsafe_entry_name(info.filename):
        return UNSAFE_NAME_MESSAGE
    if info.file_size > ARCHIVE_ENTRY_MAX_BYTES:
        return f"항목 크기({info.file_size:,}바이트)가 미리보기 한도({ARCHIVE_ENTRY_MAX_BYTES // (1024 * 1024)} MB)를 넘습니다"
    if info.file_size > ARCHIVE_ENTRY_RATIO_FLOOR_BYTES and compression_ratio(info) > ARCHIVE_ENTRY_MAX_RATIO:
        return (
            f"압축률이 비정상적으로 높아({compression_ratio(info):,.0f}:1, 한도 {ARCHIVE_ENTRY_MAX_RATIO}:1) "
            "압축 폭탄일 수 있어 열지 않습니다"
        )
    return None


@contextlib.contextmanager
def _open_zip(archive_path: Path) -> Iterator[zipfile.ZipFile]:
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            yield archive
    except zipfile.BadZipFile as exc:
        raise ArchiveEntryError(INVALID_ARCHIVE_MESSAGE, status=422) from exc


def resolve_archive_entry(archive_path: Path, entry_name: str) -> ArchiveEntry:
    """The member named exactly ``entry_name`` (no case folding, no path joining), guarded."""
    if ARCHIVED_SOURCE_SEPARATOR in entry_name:
        raise ArchiveEntryError(NESTED_ENTRY_MESSAGE, status=422)
    if is_unsafe_entry_name(entry_name):
        raise ArchiveEntryError(UNSAFE_NAME_MESSAGE, status=400)
    with _open_zip(archive_path) as archive:
        try:
            info = archive.getinfo(entry_name)
        except KeyError as exc:
            raise ArchiveEntryError(MISSING_ENTRY_MESSAGE, status=404) from exc
    reason = refusal_reason(info)
    if reason is not None:
        raise ArchiveEntryError(reason, status=422)
    return ArchiveEntry(
        archive_path=archive_path,
        entry_name=info.filename,
        size=info.file_size,
        compressed_size=info.compress_size,
        modified_at=zip_info_modified_at(info),
    )


def source_size(source: SourceFile) -> int:
    return source.size if isinstance(source, ArchiveEntry) else source.stat().st_size


@contextlib.contextmanager
def open_source(source: SourceFile) -> Iterator[BinaryIO]:
    """``source``'s bytes for reading: a file as is, an entry decompressed as it is read.

    :mod:`zipfile` stops an entry at its declared size, so a forged header cannot stream more
    than the size the guards approved.
    """
    if isinstance(source, ArchiveEntry):
        with _open_zip(source.archive_path) as archive, archive.open(source.entry_name, "r") as handle:
            yield handle
    else:
        with source.open("rb") as handle:
            yield handle


def hash_source(source: SourceFile, *, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    hashers = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with open_source(source) as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def entry_image_size(entry: ArchiveEntry) -> dict[str, int]:
    """The member's pixel size from its image header; empty when Pillow is absent or cannot read it."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ModuleNotFoundError:
        return {}
    with open_source(entry) as handle:
        try:
            with Image.open(handle) as image:
                return {"width": image.width, "height": image.height}
        except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
            return {}


def list_archive_entries(archive_path: Path, *, offset: int, limit: int) -> dict[str, object]:
    """A page of the archive's members as the console lists them (central directory only)."""
    limit = max(1, min(limit, ARCHIVE_LIST_MAX_ENTRIES))
    with _open_zip(archive_path) as archive:
        infos = archive.infolist()
    page = infos[offset : offset + limit]
    entries = []
    for info in page:
        reason = refusal_reason(info)
        entries.append(
            {
                "name": info.filename,
                "path": f"{archive_path}{ARCHIVED_SOURCE_SEPARATOR}{info.filename}",
                "is_directory": info.is_dir(),
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "modified_at": zip_info_modified_at(info),
                "encrypted": bool(info.flag_bits & 0x1),
                "nested_archive": PurePosixPath(info.filename).suffix.lower() in NESTED_ARCHIVE_SUFFIXES,
                "openable": reason is None,
                "refusal_reason": reason or "",
            }
        )
    return {
        "path": str(archive_path),
        "container_type": "zip",
        "total": len(infos),
        "offset": offset,
        "limit": limit,
        "returned": len(entries),
        "has_next": offset + len(entries) < len(infos),
        "entries": entries,
        "limits": {
            "max_entry_bytes": ARCHIVE_ENTRY_MAX_BYTES,
            "max_compression_ratio": ARCHIVE_ENTRY_MAX_RATIO,
            "ratio_floor_bytes": ARCHIVE_ENTRY_RATIO_FLOOR_BYTES,
            "writes_extracted_files": False,
        },
    }
