"""Step exception classification: the output volume filled up while a step was writing (R8 T-352).

A disk-full error raised by a run step -- ``OSError`` ENOSPC (Windows error 112/39) or SQLite's
"database or disk is full" -- becomes :class:`OutputDiskFull` (code ``OUTPUT_DISK_FULL``) whose
text is the Korean step status "실패 — 결과 폴더 여유 부족(여유 m · 쓰다 만 파일 k개 지움)".

Cleanup is deliberately narrow (review WB-10/11 P1-1, WB-12 P1-1): only this tool's own run
outputs are candidates, never an extracted evidence tree. Removed are (a) the file named by the
failing error (``filename`` only, never ``filename2`` -- the destination of a failed rename is a
finished earlier output) when it is a ``rapidtriage-*`` run output outside every extracted tree,
did not exist before the run (``preexisting``) and was modified since the run started, (b) temp
files the run writes before renaming into place (``rapidtriage-*`` names ending in ``.tmp`` /
``.partial``) and (c) this run's own ``rapidtriage-*.json``/``.jsonl`` outputs left unclosed --
(b) and (c) only in the result folder itself and its own output folders (``artifacts``,
``carving``), and only when modified since the run started. Audit and log histories
(``rapidtriage-export-audit.jsonl``, ``*-audit*``, ``*.log``) are appended to, never rewritten:
they are never removed nor changed; a torn last line is reported instead ("감사 기록 마지막 줄
불완전", ``torn_histories``). Every removed path is kept (relative to the result folder) on the
exception and written into the progress file.

Extraction (WB-12 P1-2): the native engine unlinks a file it could not write, so the free space
right after extraction says little. :class:`FreeSpaceSampler` samples the result volume while the
extraction runs and keeps the minimum; per-file errors > 0 and a sampled minimum below
``max(NEAR_FULL_FREE_BYTES, 2 x the largest drop between two samples)`` = a full disk. Limits: a
volume that filled faster than the sampling caught (a burst far above the observed rate) is still
missed; a nearly full volume with ordinary read errors is reported as full (safe direction).
"""

from __future__ import annotations

import errno
import os
import shutil
import sqlite3
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..audit import EXPORT_AUDIT_LOG_NAME

__all__ = [
    "EXTRACTED_TREE_NAMES",
    "NEAR_FULL_FREE_BYTES",
    "OUTPUT_DISK_FULL",
    "FreeSpaceSampler",
    "OutputDiskFull",
    "classify_step_exception",
    "extraction_disk_full_error",
    "find_torn_histories",
    "format_byte_count",
    "is_disk_full_error",
    "is_history_file",
    "remove_partial_outputs",
    "snapshot_existing_outputs",
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
#: Seconds between two free-space samples while an image is extracted.
FREE_SPACE_SAMPLE_SECONDS = 1.0
#: Append-only histories: never removed or rewritten by the cleanup (WB-12 P1-1).
_HISTORY_SUFFIXES = (".log",)
_HISTORY_MARKERS = ("audit",)


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
        torn_histories: list[str] | None = None,
        min_free_bytes: int | None = None,
    ) -> None:
        super().__init__(errno.ENOSPC, "output disk full")
        self.stage = stage
        self.free_bytes = free_bytes
        self.removed_files = removed_files
        self.removed_bytes = removed_bytes
        self.extraction_errors = extraction_errors
        self.torn_histories = list(torn_histories or [])
        self.min_free_bytes = min_free_bytes
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
            if self.min_free_bytes is not None:
                parts.append(f"추출 중 최소 여유 {format_byte_count(self.min_free_bytes)}")
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
        for name in self.torn_histories:
            lines.append(f"감사 기록 마지막 줄 불완전: {name} (지우거나 고치지 않음)")
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


def is_history_file(path: Path) -> bool:
    """An append-only audit or log history (never removed or rewritten by the cleanup)."""
    name = path.name.lower()
    return name == EXPORT_AUDIT_LOG_NAME or name.endswith(_HISTORY_SUFFIXES) or any(
        marker in name for marker in _HISTORY_MARKERS
    )


def _own_leftover(path: Path, *, since_epoch: float) -> bool:
    """A ``rapidtriage-*`` temp file, or an unclosed ``rapidtriage-*.json(l)``, written by this run."""
    name = path.name.lower()
    if not name.startswith(_OWN_OUTPUT_PREFIX) or is_history_file(path):
        return False
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_mtime < since_epoch:
            return False
    except OSError:
        return False
    return name.endswith(_TEMP_OUTPUT_SUFFIXES) or _looks_half_written(path)


def snapshot_existing_outputs(output_dir: Path) -> frozenset[str]:
    """Relative names of the ``rapidtriage-*`` files present before the run (result folder and its
    own output folders), so the cleanup never removes an earlier run's output by name."""
    names: set[str] = set()
    for folder in (output_dir, *(output_dir / sub for sub in _OWN_OUTPUT_SUBDIRS)):
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            parts = _relative_parts(Path(entry.path), output_dir)
            if parts:
                names.add("/".join(parts).lower())
    return frozenset(names)


def find_torn_histories(output_dir: Path, *, since_epoch: float) -> list[str]:
    """History files (audit / log) in the result folder whose last line this run left unterminated."""
    torn: list[str] = []
    try:
        entries = list(os.scandir(output_dir))
    except OSError:
        return torn
    for entry in entries:
        path = Path(entry.path)
        if not is_history_file(path):
            continue
        try:
            stat_result = path.stat()
            if not path.is_file() or stat_result.st_mtime < since_epoch or stat_result.st_size == 0:
                continue
            with path.open("rb") as handle:
                handle.seek(max(0, stat_result.st_size - 1))
                if handle.read(1) != b"\n":
                    torn.append(path.name)
        except OSError:
            continue
    return sorted(torn)


def remove_partial_outputs(
    output_dir: Path,
    exc: BaseException,
    *,
    since_epoch: float,
    preexisting: frozenset[str] | None = None,
) -> tuple[list[str], int]:
    """Remove the run outputs a failed write left half-written; returns (relative paths, bytes).

    See the module docstring for the rule. Extracted evidence trees (``EXTRACTED_TREE_NAMES``) are
    never entered, files of an earlier run (older than ``since_epoch``, or named in
    ``preexisting``) are kept, histories are never touched, and nothing outside ``output_dir`` is.
    """
    candidates: dict[str, Path] = {}
    name = getattr(exc, "filename", None)  # never filename2: a rename destination is a finished output
    if isinstance(name, (str, os.PathLike)) and str(name):
        path = Path(name)
        parts = _relative_parts(path, output_dir)
        if (
            parts
            and not _in_extracted_tree(parts)
            and path.name.lower().startswith(_OWN_OUTPUT_PREFIX)
            and not is_history_file(path)
            and "/".join(parts).lower() not in (preexisting or frozenset())
            and _modified_since(path, since_epoch)
        ):
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


def _modified_since(path: Path, since_epoch: float) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and path.stat().st_mtime >= since_epoch
    except OSError:
        return False


def _free_bytes(folder: Path) -> int | None:
    try:
        return int(shutil.disk_usage(folder).free)
    except OSError:
        return None


class FreeSpaceSampler:
    """Samples the result volume's free space from a daemon thread while an extraction runs.

    Keeps the minimum and the largest drop between two consecutive samples (the write rate per
    interval), so :func:`extraction_disk_full_error` can tell "filled, then the engine unlinked
    the file it could not write" from "plenty of room all along". ``usage`` is injectable for tests.
    """

    def __init__(
        self,
        folder: Path,
        *,
        interval: float = FREE_SPACE_SAMPLE_SECONDS,
        usage: Callable[[Path], Any] = shutil.disk_usage,
    ) -> None:
        self.folder = Path(folder)
        self.interval = interval
        self._usage = usage
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last: int | None = None
        self.min_free: int | None = None
        self.max_drop = 0
        self.samples = 0

    def sample(self) -> int | None:
        try:
            free = int(self._usage(self.folder).free)
        except (OSError, AttributeError, TypeError, ValueError):
            return None
        with self._lock:
            self.samples += 1
            if self._last is not None and self._last > free:
                self.max_drop = max(self.max_drop, self._last - free)
            self._last = free
            self.min_free = free if self.min_free is None else min(self.min_free, free)
        return free

    def near_full_threshold(self) -> int:
        return max(NEAR_FULL_FREE_BYTES, 2 * self.max_drop)

    def summary(self) -> dict[str, int | None]:
        with self._lock:
            return {"min_free_bytes": self.min_free, "max_drop_bytes": self.max_drop, "samples": self.samples}

    def start(self) -> FreeSpaceSampler:
        self.sample()
        if self.interval > 0:
            self._thread = threading.Thread(target=self._run, name="rapidtriage-free-space-heartbeat", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self.sample()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.sample()

    def __enter__(self) -> FreeSpaceSampler:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


def extraction_disk_full_error(
    output_dir: Path,
    extraction_result: Mapping[str, object],
    *,
    sampler: FreeSpaceSampler | None = None,
) -> OSError | None:
    """ENOSPC for an image extraction that recorded per-file errors on a volume that ran (nearly) full.

    The native E01 engine counts a file it could not write as one error, unlinks its partial copy
    and goes on (it records neither the error kind nor the size), so a full volume during
    extraction ends "normally" with a smaller tree and plenty of free space afterwards. Without an
    engine change the signal is: errors > 0 and either the free space sampled during the
    extraction (``sampler``) fell below ``sampler.near_full_threshold()`` or the volume has less
    than ``NEAR_FULL_FREE_BYTES`` free right after it.
    """
    errors = 0
    for entry in extraction_result.get("command_history") or ():
        if isinstance(entry, Mapping):
            value = entry.get("errors")
            if isinstance(value, int) and not isinstance(value, bool):
                errors += max(0, value)
    if errors <= 0:
        return None
    sampled_full = sampler is not None and sampler.min_free is not None and sampler.min_free < sampler.near_full_threshold()
    free = _free_bytes(output_dir)
    if not sampled_full and (free is None or free >= NEAR_FULL_FREE_BYTES):
        return None
    error = OSError(errno.ENOSPC, f"extraction could not write {errors} file(s); output volume nearly full")
    error.extraction_errors = errors  # type: ignore[attr-defined]
    error.min_free_bytes = sampler.min_free if sampler is not None else None  # type: ignore[attr-defined]
    return error


def classify_step_exception(
    exc: BaseException,
    *,
    stage: str,
    output_dir: Path,
    since_epoch: float,
    preexisting: frozenset[str] | None = None,
) -> BaseException:
    """``OutputDiskFull`` for a disk-full error raised by a step (half-written run outputs removed);
    any other exception is returned unchanged. Free space is read before the cleanup."""
    if isinstance(exc, OutputDiskFull) or not is_disk_full_error(exc):
        return exc
    free = _free_bytes(output_dir)
    removed, removed_bytes = remove_partial_outputs(output_dir, exc, since_epoch=since_epoch, preexisting=preexisting)
    extraction_errors = getattr(exc, "extraction_errors", 0)
    min_free = getattr(exc, "min_free_bytes", None)
    return OutputDiskFull(
        torn_histories=find_torn_histories(output_dir, since_epoch=since_epoch),
        min_free_bytes=min_free if isinstance(min_free, int) else None,
        stage=stage,
        free_bytes=free,
        removed_files=removed,
        removed_bytes=removed_bytes,
        cause=exc,
        extraction_errors=extraction_errors if isinstance(extraction_errors, int) else 0,
    )
