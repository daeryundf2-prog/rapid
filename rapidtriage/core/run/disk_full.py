"""Step exception classification: the output volume filled up while a step was writing (R8 T-352).

A disk-full ``OSError`` (ENOSPC, Windows error 112/39) raised by a run step becomes
:class:`OutputDiskFull` (code ``OUTPUT_DISK_FULL``) whose text is the Korean step status
"실패 — 결과 폴더 여유 부족(필요 n · 여유 m)". The files the failed write left half-written in the
output folder are removed so the run can be resumed; collection and parsing are not touched.
"""

from __future__ import annotations

import errno
import os
import shutil
from pathlib import Path

__all__ = [
    "OUTPUT_DISK_FULL",
    "OutputDiskFull",
    "classify_step_exception",
    "format_byte_count",
    "is_disk_full_error",
    "remove_partial_outputs",
]

OUTPUT_DISK_FULL = "OUTPUT_DISK_FULL"
#: Windows ERROR_DISK_FULL (112) and ERROR_HANDLE_DISK_FULL (39).
_WINDOWS_DISK_FULL_ERRORS = frozenset({112, 39})
#: Suffixes of temporary files a writer renames into place; always half-written when left behind.
_TEMP_OUTPUT_SUFFIXES = (".tmp", ".partial")
_TAIL_PROBE_BYTES = 64


class OutputDiskFull(OSError):
    """A step failed because the output folder's volume ran out of space (``OUTPUT_DISK_FULL``).

    ``str()`` is the Korean step status ("실패 — 결과 폴더 여유 부족(필요 n · 여유 m)"); the
    half-written files were removed and the run stays resumable (``--resume``).
    """

    code = OUTPUT_DISK_FULL

    def __init__(
        self,
        *,
        stage: str,
        required_bytes: int,
        free_bytes: int | None,
        removed_files: list[str],
        cause: BaseException,
    ) -> None:
        super().__init__(errno.ENOSPC, "output disk full")
        self.stage = stage
        self.required_bytes = required_bytes
        self.free_bytes = free_bytes
        self.removed_files = removed_files
        self.cause_message = str(cause)

    @property
    def message_ko(self) -> str:
        required = f"{format_byte_count(self.required_bytes)} 이상" if self.required_bytes else "알 수 없음"
        free = format_byte_count(self.free_bytes) if self.free_bytes is not None else "알 수 없음"
        return f"실패 — 결과 폴더 여유 부족(필요 {required} · 여유 {free})"

    def __str__(self) -> str:
        return self.message_ko


def format_byte_count(value: int) -> str:
    size = float(max(0, int(value)))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"  # pragma: no cover - loop always returns


def is_disk_full_error(exc: BaseException) -> bool:
    """True for ``OSError`` ENOSPC (POSIX, and what Python maps Windows 112 to) or Windows 112/39."""
    if isinstance(exc, OutputDiskFull):
        return True
    if not isinstance(exc, OSError):
        return False
    return exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) in _WINDOWS_DISK_FULL_ERRORS


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
    except (OSError, ValueError):
        return False
    return True


def _looks_half_written(path: Path) -> bool:
    """A JSON document not closed by ``}``/``]`` or a JSONL file not ending in a newline."""
    suffix = path.suffix.lower()
    if suffix not in (".json", ".jsonl"):
        return False
    try:
        size = path.stat().st_size
        if size == 0:
            return suffix == ".json"
        with path.open("rb") as handle:
            handle.seek(max(0, size - _TAIL_PROBE_BYTES))
            tail = handle.read()
    except OSError:
        return False
    if suffix == ".jsonl":
        return not tail.endswith(b"\n")
    return not tail.rstrip().endswith((b"}", b"]"))


def remove_partial_outputs(output_dir: Path, exc: BaseException, *, since_epoch: float) -> tuple[list[str], int]:
    """Remove the files a failed write left half-written in ``output_dir``; returns (paths, bytes).

    Removed: the file named by the error, every leftover ``*.tmp``/``*.partial`` file, and every
    ``.json``/``.jsonl`` output modified since the run started that is not closed. Complete outputs
    of this or an earlier run are kept, so the run can be resumed. Never touches anything outside
    ``output_dir`` (the evidence is never written).
    """
    candidates: dict[str, Path] = {}
    for name in (getattr(exc, "filename", None), getattr(exc, "filename2", None)):
        if isinstance(name, (str, os.PathLike)) and str(name):
            path = Path(name)
            if path.is_file() and _inside(path, output_dir):
                candidates[str(path.resolve())] = path
    for folder, _dirs, files in os.walk(output_dir):
        for file_name in files:
            path = Path(folder) / file_name
            try:
                modified = path.stat().st_mtime
            except OSError:
                continue
            if file_name.endswith(_TEMP_OUTPUT_SUFFIXES) or (modified >= since_epoch and _looks_half_written(path)):
                candidates[str(path.resolve())] = path
    removed: list[str] = []
    removed_bytes = 0
    for key in sorted(candidates):
        path = candidates[key]
        try:
            size = path.stat().st_size
            path.unlink()
        except OSError:
            continue
        removed.append(str(path))
        removed_bytes += size
    return removed, removed_bytes


def classify_step_exception(
    exc: BaseException,
    *,
    stage: str,
    output_dir: Path,
    since_epoch: float,
) -> BaseException:
    """``OutputDiskFull`` for a disk-full ``OSError`` raised by a step (half-written files removed);
    any other exception is returned unchanged."""
    if isinstance(exc, OutputDiskFull) or not is_disk_full_error(exc):
        return exc
    removed, removed_bytes = remove_partial_outputs(output_dir, exc, since_epoch=since_epoch)
    try:
        free: int | None = int(shutil.disk_usage(output_dir).free)
    except OSError:
        free = None
    return OutputDiskFull(
        stage=stage,
        required_bytes=removed_bytes,
        free_bytes=free,
        removed_files=removed,
        cause=exc,
    )
