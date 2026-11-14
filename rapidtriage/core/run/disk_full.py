"""Step exception classification: the output volume filled up while a step was writing (R8 T-352).

A disk-full error raised by a run step -- ``OSError`` ENOSPC (Windows error 112/39) or SQLite's
"database or disk is full" -- becomes :class:`OutputDiskFull` (code ``OUTPUT_DISK_FULL``) whose
text is the Korean step status "실패 — 결과 폴더 여유 부족(여유 m · 쓰다 만 파일 k개 지움)".

Cleanup is deliberately narrow (review WB-10/11 P1-1): only this tool's own run outputs are
candidates, never an extracted evidence tree. Removed are (a) the file named by the failing
error when it is a run output outside every extracted tree, (b) temp files the run writes before
renaming into place (``rapidtriage-*`` names ending in ``.tmp`` / ``.partial``) and (c) this run's
own ``rapidtriage-*.json``/``.jsonl`` outputs left unclosed -- (b) and (c) only in the result
folder itself and its own output folders (``artifacts``, ``carving``), and only when modified
since the run started. Every removed path is kept (relative to the result folder) on the
exception and written into the progress file and the problem item.
"""

from __future__ import annotations

import errno
import os
import shutil
import sqlite3
from collections.abc import Mapping
from pathlib import Path

__all__ = [
    "EXTRACTED_TREE_NAMES",
    "NEAR_FULL_FREE_BYTES",
    "OUTPUT_DISK_FULL",
    "OutputDiskFull",
    "classify_step_exception",
    "extraction_disk_full_error",
    "format_byte_count",
    "is_disk_full_error",
    "remove_partial_outputs",
]

OUTPUT_DISK_FULL = "OUTPUT_DISK_FULL"
#: Windows ERROR_DISK_FULL (112) and ERROR_HANDLE_DISK_FULL (39).
_WINDOWS_DISK_FULL_ERRORS = frozenset({112, 39})
#: SQLite primary result code SQLITE_FULL ("database or disk is full").
_SQLITE_FULL = 13
#: Folders under the result folder that hold copies of the evidence (extracted / staged trees,
#: export copies). Nothing below them is ever removed.
EXTRACTED_TREE_NAMES = frozenset(
    {
        "_e01",
        "_disk_image",
        "_archive_image",
        "_virtual_disk",
        "docs-extract",
        "files-extract",
        "extract",
        "mobile-inner",
        "incremental-delta-scope",
    }
)
#: The run's own output folders scanned for its temp / unclosed outputs (not recursive).
_OWN_OUTPUT_SUBDIRS = ("artifacts", "carving")
#: Every run output and every temp file the run writes starts with this.
_OWN_OUTPUT_PREFIX = "rapidtriage-"
_TEMP_OUTPUT_SUFFIXES = (".tmp", ".partial")
_TAIL_PROBE_BYTES = 64
#: Free space below this after an extraction that recorded per-file errors = the volume filled.
NEAR_FULL_FREE_BYTES = 64 * 1024 * 1024


class OutputDiskFull(OSError):
    """A step failed because the output folder's volume ran out of space (``OUTPUT_DISK_FULL``).

    ``str()`` is the Korean step status, then the removed files; the run stays resumable
    (``--resume``) except after an extraction that could not write some files (``extraction_errors``).
    """

    code = OUTPUT_DISK_FULL

    def __init__(
        self,
        *,
        stage: str,
        free_bytes: int | None,
        removed_files: list[str],
        cause: BaseException,
        removed_bytes: int = 0,
        extraction_errors: int = 0,
    ) -> None:
        super().__init__(errno.ENOSPC, "output disk full")
        self.stage = stage
        self.free_bytes = free_bytes
        self.removed_files = removed_files
        self.removed_bytes = removed_bytes
        self.extraction_errors = extraction_errors
        self.cause_message = str(cause)

    @property
    def status_ko(self) -> str:
        """The step status: free space measured when the error was caught (before cleanup)."""
        free = format_byte_count(self.free_bytes) if self.free_bytes is not None else "알 수 없음"
        parts = [f"여유 {free}"]
        if self.removed_files:
            parts.append(f"쓰다 만 파일 {len(self.removed_files)}개 지움")
        if self.extraction_errors:
            parts.append(f"추출하지 못한 파일 {self.extraction_errors}개")
        return f"실패 — 결과 폴더 여유 부족({' · '.join(parts)})"

    @property
    def message_ko(self) -> str:
        lines = [self.status_ko]
        if self.extraction_errors:
            lines.append("이어서 처리는 추출을 다시 하지 않으니 공간을 비운 뒤 새 결과 폴더로 다시 처리하세요")
        if self.removed_files:
            shown = ", ".join(self.removed_files[:5])
            more = f" 외 {len(self.removed_files) - 5}개" if len(self.removed_files) > 5 else ""
            lines.append(f"지운 파일(결과 폴더 기준): {shown}{more}")
        return "; ".join(lines)

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
    """True for ``OSError`` ENOSPC / Windows 112/39 and SQLite "database or disk is full"."""
    if isinstance(exc, OutputDiskFull):
        return True
    if isinstance(exc, sqlite3.OperationalError):
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int) and (code & 0xFF) == _SQLITE_FULL:
            return True
        return "database or disk is full" in str(exc).lower()
    if not isinstance(exc, OSError):
        return False
    return exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) in _WINDOWS_DISK_FULL_ERRORS


def _relative_parts(path: Path, folder: Path) -> tuple[str, ...] | None:
    try:
        return path.resolve().relative_to(folder.resolve()).parts
    except (OSError, ValueError):
        return None


def _in_extracted_tree(parts: tuple[str, ...]) -> bool:
    return any(part.lower() in EXTRACTED_TREE_NAMES for part in parts[:-1])


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


def _own_leftover(path: Path, *, since_epoch: float) -> bool:
    """A ``rapidtriage-*`` temp file, or an unclosed ``rapidtriage-*.json(l)``, written by this run."""
    name = path.name.lower()
    if not name.startswith(_OWN_OUTPUT_PREFIX):
        return False
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_mtime < since_epoch:
            return False
    except OSError:
        return False
    return name.endswith(_TEMP_OUTPUT_SUFFIXES) or _looks_half_written(path)


def remove_partial_outputs(output_dir: Path, exc: BaseException, *, since_epoch: float) -> tuple[list[str], int]:
    """Remove the run outputs a failed write left half-written; returns (relative paths, bytes).

    See the module docstring for the rule. Extracted evidence trees (``EXTRACTED_TREE_NAMES``) are
    never entered, files of an earlier run (older than ``since_epoch``) are kept, and nothing
    outside ``output_dir`` is touched.
    """
    candidates: dict[str, Path] = {}
    for name in (getattr(exc, "filename", None), getattr(exc, "filename2", None)):
        if isinstance(name, (str, os.PathLike)) and str(name):
            path = Path(name)
            parts = _relative_parts(path, output_dir)
            if parts and not _in_extracted_tree(parts) and path.is_file() and not path.is_symlink():
                candidates["/".join(parts)] = path
    for folder in (output_dir, *(output_dir / sub for sub in _OWN_OUTPUT_SUBDIRS)):
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            path = Path(entry.path)
            if _own_leftover(path, since_epoch=since_epoch):
                parts = _relative_parts(path, output_dir)
                if parts:
                    candidates["/".join(parts)] = path
    removed: list[str] = []
    removed_bytes = 0
    for relative in sorted(candidates):
        path = candidates[relative]
        try:
            size = path.stat().st_size
            path.unlink()
        except OSError:
            continue
        removed.append(relative)
        removed_bytes += size
    return removed, removed_bytes


def _free_bytes(folder: Path) -> int | None:
    try:
        return int(shutil.disk_usage(folder).free)
    except OSError:
        return None


def extraction_disk_full_error(output_dir: Path, extraction_result: Mapping[str, object]) -> OSError | None:
    """ENOSPC for an image extraction that recorded per-file errors on a (nearly) full volume.

    The native E01 engine counts a file it could not write as one error and goes on (it does not
    record the error kind), so a full volume during extraction ends "normally" with a smaller tree.
    Without an engine change this is the detectable signal: errors > 0 and the result folder's
    volume has less than ``NEAR_FULL_FREE_BYTES`` free right after the extraction.
    """
    errors = 0
    for entry in extraction_result.get("command_history") or ():
        if isinstance(entry, Mapping):
            value = entry.get("errors")
            if isinstance(value, int) and not isinstance(value, bool):
                errors += max(0, value)
    if errors <= 0:
        return None
    free = _free_bytes(output_dir)
    if free is None or free >= NEAR_FULL_FREE_BYTES:
        return None
    error = OSError(errno.ENOSPC, f"extraction could not write {errors} file(s); output volume nearly full")
    error.extraction_errors = errors  # type: ignore[attr-defined]
    return error


def classify_step_exception(
    exc: BaseException,
    *,
    stage: str,
    output_dir: Path,
    since_epoch: float,
) -> BaseException:
    """``OutputDiskFull`` for a disk-full error raised by a step (half-written run outputs removed);
    any other exception is returned unchanged. Free space is read before the cleanup."""
    if isinstance(exc, OutputDiskFull) or not is_disk_full_error(exc):
        return exc
    free = _free_bytes(output_dir)
    removed, removed_bytes = remove_partial_outputs(output_dir, exc, since_epoch=since_epoch)
    extraction_errors = getattr(exc, "extraction_errors", 0)
    return OutputDiskFull(
        stage=stage,
        free_bytes=free,
        removed_files=removed,
        removed_bytes=removed_bytes,
        cause=exc,
        extraction_errors=extraction_errors if isinstance(extraction_errors, int) else 0,
    )
