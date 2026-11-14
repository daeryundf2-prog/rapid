"""Disk free-space check before a run starts (R8 T-186, GAP-183·278 / IS-160; WB-9 P1-1·P1-2).

:func:`check_output_space` estimates how many bytes a run will write for an evidence and compares
that with the free space of the volume that will hold the output folder (``shutil.disk_usage``).
The answer is ``{estimated_bytes, free_bytes, ok, level, code, message, basis}``. It is **advice
only**: no route refuses a run because of it (until the console can confirm and override, T-079),
the result rides along as ``preflight_space`` in the 202 body.

* ``level="ok"``    -- free space covers the estimate plus its error margin (:data:`ESTIMATE_MARGIN`).
* ``level="warn"``  -- free space may not cover the output (``code`` DISK_SPACE_LOW).
* ``level="block"`` -- only for an estimate that is a reliable upper bound (a raw image's selected
  partition size) and that bound exceeds free space (``ok=False``, DISK_SPACE_INSUFFICIENT). Still
  not a refusal; the message says the bound is a maximum.
* ``level="unknown"`` -- no estimate, no free-space reading, or (E01) an estimate dominated by the
  partition cap / an unknown compression ratio when free space is below it.

The estimate model (read only, metadata only — no evidence content is read beyond the partition table).
Every message says "추정" and names its basis (:data:`METHOD_BASIS_KO`):

* E01/Ex01: today's engine copies the selected partition's allocated files into the output. Allocated
  bytes are unknown before the run; they are approximated from the **compressed segment bytes** times
  :data:`EWF_EXPANSION` (fitted on one real image, IMG-B), scaled by the partition's share of the media
  and capped at the partition size. When the cap decides (uncompressed or incompressible images) or no
  partition was read, the ratio says nothing: the level is at most ``warn`` / ``unknown``.
* raw/dd images: the selected partition size is the upper bound of the copied files.
* other evidence files (VHD/VMDK, archives): the file size (not a bound: archives can expand).
* folders: nothing is copied unless extraction is on; the output is the derived rows, which grow with
  the **entry count** (:data:`FOLDER_BYTES_PER_ENTRY`), plus a small share of the content
  (:data:`FOLDER_CONTENT_SHARE`, parsed logs / databases); extraction adds the copied bytes (capped by
  ``max_extract_size_bytes``). The walk is capped by entries and time (a lower bound when cut).

Request caps are respected: ``max_file_count`` caps a folder's counted entries; the native E01 engine's
file cap (``MAX_NATIVE_EXTRACT_FILES``) and resume / overwrite are disclosed in ``basis.notes`` and keep
the level at ``warn`` at most. The image / folder part of the estimate is cached per
``(path, size, mtime)`` for a short time, so the preview and the start of the same run walk once.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

__all__ = [
    "DISK_SPACE_INSUFFICIENT",
    "DISK_SPACE_LOW",
    "ESTIMATE_MARGIN",
    "EWF_EXPANSION",
    "METHOD_BASIS_KO",
    "OUTPUT_OVERHEAD",
    "check_output_space",
    "estimate_from_sizes",
    "estimate_output_bytes",
    "format_bytes",
    "preflight_space_for",
    "space_verdict",
]

DISK_SPACE_LOW = "DISK_SPACE_LOW"
DISK_SPACE_INSUFFICIENT = "DISK_SPACE_INSUFFICIENT"

#: Allocated bytes per compressed EWF segment byte (IMG-B: 64.1 GB tree / 18.5 GB segments ≈ 3.46).
#: One data point: an uncompressed image gives ~1, a text-heavy one 6+.
EWF_EXPANSION = 3.5
#: Output bytes beyond the copied files, as a share of them (IMG-B: (71.6 - 64.1) / 64.1 ≈ 0.117).
OUTPUT_OVERHEAD = 0.12
#: The estimate's error target (±30%): free space below ``estimate × (1 + margin)`` is a warning.
ESTIMATE_MARGIN = 0.30
#: Folder evidence: derived output bytes per file / folder entry (JSONL rows, index, case DB rows).
FOLDER_BYTES_PER_ENTRY = 4096
#: Folder evidence: share of the content bytes that becomes parsed rows (event logs, browser DBs …).
FOLDER_CONTENT_SHARE = 0.02
#: Bounded folder walk: entries visited / seconds spent before the count is reported as a lower bound.
FOLDER_WALK_LIMIT = 200_000
FOLDER_WALK_SECONDS = 2.0
#: Seconds an estimate is reused for the same (path, size, mtime, options): the preview + start pair.
CACHE_SECONDS = 120.0

#: Korean basis of each estimate method (named in every message).
METHOD_BASIS_KO = {
    "ewf-compressed-segments": f"E01 압축 세그먼트 크기 × {EWF_EXPANSION}(실측 이미지 1개로 맞춘 비율)",
    "ewf-partition-cap": "E01 선택 파티션 크기(압축 비율로는 알 수 없어 파티션 크기를 상한으로 씀)",
    "ewf-no-partition": "E01 세그먼트 크기(파티션을 읽지 못해 압축 비율을 적용할 수 없음)",
    "raw-partition-upper-bound": "원시 이미지의 선택 파티션 크기(복사될 파일의 최대치)",
    "evidence-file-size": "증거 파일 크기",
    "folder-entries": f"폴더 항목 수 × {FOLDER_BYTES_PER_ENTRY // 1024} KB + 내용의 {int(FOLDER_CONTENT_SHARE * 100)}%",
}
#: Methods whose estimate is a reliable upper bound (the only ones that may report ``block``).
RELIABLE_UPPER_BOUND = frozenset({"raw-partition-upper-bound"})
#: Methods whose estimate says nothing about the real size when free space is below it.
UNKNOWN_WHEN_SHORT = frozenset({"ewf-partition-cap", "ewf-no-partition"})

DiskUsage = Callable[[str], Any]

_cache: dict[tuple[object, ...], tuple[float, dict[str, object]]] = {}
_cache_lock = threading.Lock()


def format_bytes(value: int | None) -> str:
    """``71.6 GB`` style (decimal units, one decimal place) for Korean messages."""
    if value is None:
        return "알 수 없음"
    size = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{size:.1f} TB"


def estimate_from_sizes(
    kind: str,
    *,
    evidence_bytes: int,
    media_bytes: int | None = None,
    partition_bytes: int | None = None,
    entry_count: int = 0,
    extract_bytes: int = 0,
) -> tuple[int, str]:
    """``(estimated output bytes, method)`` from sizes alone (pure; the model of the module docstring)."""
    evidence_bytes = max(0, int(evidence_bytes))
    if kind == "ewf":
        if not partition_bytes:
            # No partition table: no share, no ratio; the segment bytes (capped at the media) are all we have.
            copied = float(min(evidence_bytes, media_bytes) if media_bytes else evidence_bytes)
            return int(copied * (1.0 + OUTPUT_OVERHEAD)), "ewf-no-partition"
        share = min(1.0, max(0.0, partition_bytes / media_bytes)) if media_bytes else 1.0
        copied = evidence_bytes * EWF_EXPANSION * share
        method = "ewf-compressed-segments"
        if copied >= partition_bytes:
            copied, method = float(partition_bytes), "ewf-partition-cap"
    elif kind == "raw":
        copied = float(partition_bytes or media_bytes or evidence_bytes)
        method = "raw-partition-upper-bound"
    elif kind == "folder":
        derived = max(0, entry_count) * FOLDER_BYTES_PER_ENTRY + evidence_bytes * FOLDER_CONTENT_SHARE
        return int(derived + max(0, extract_bytes) * (1.0 + OUTPUT_OVERHEAD)), "folder-entries"
    else:
        copied = float(evidence_bytes)
        method = "evidence-file-size"
    return int(copied * (1.0 + OUTPUT_OVERHEAD)), method


def _folder_walk(root: Path, entry_limit: int) -> tuple[int, int, bool, str]:
    """``(bytes, entries, complete, stop reason)``; stops after ``entry_limit`` entries or
    :data:`FOLDER_WALK_SECONDS` (then the counts are lower bounds)."""
    total = seen = 0
    deadline = time.monotonic() + FOLDER_WALK_SECONDS
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    seen += 1
                    if seen > entry_limit:
                        return total, seen - 1, False, "entries"
                    if seen % 256 == 0 and time.monotonic() > deadline:
                        return total, seen, False, "time"
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total, seen, True, ""


def _image_partition(image: Path, segments: list[Path], kind: str, start_sector: int | None) -> tuple[int | None, int | None, str]:
    """``(media_bytes, selected partition bytes, note)`` from the partition table (read only).

    EWF sets are opened with every discovered segment (past ``.E99``, WB-9 P1-4) through the
    engine's read-only opener; raw images through its stdlib handle."""
    from ...core.e01_native import (
        NativeImageError,
        RawMediaHandle,
        native_partition_table,
        open_ewf_segments,
        select_native_partition,
    )

    handle: Any = None
    try:
        handle = open_ewf_segments(segments) if kind == "ewf" else RawMediaHandle(image)
        media = int(handle.get_media_size())
        partitions, _sector_size = native_partition_table(handle)
    except (NativeImageError, OSError, ValueError, RuntimeError) as exc:
        return None, None, f"파티션 표를 읽지 못함: {str(exc)[:160]}"
    finally:
        if handle is not None:
            with contextlib.suppress(Exception):  # close errors are irrelevant to a read-only probe
                handle.close()
    try:
        selected = select_native_partition(partitions, preferred_start_sector=start_sector)
    except ValueError as exc:
        return media, None, f"선택 파티션을 찾지 못함: {str(exc)[:160]}"
    for row in partitions:
        if selected is not None and int(row.get("start_sector") or 0) == selected:
            size = int(row.get("size_bytes") or 0) or int(row.get("sector_count") or 0) * int(row.get("sector_size_bytes") or 512)
            return media, size or None, ""
    return media, None, "지원하는 파일 시스템 파티션이 없음"


def _evidence_basis(source: Path, partition_start_sector: int | None, max_file_count: int, extract: bool, max_extract: int) -> dict[str, object]:
    basis: dict[str, object] = {"estimated_bytes": None, "method": "", "evidence_kind": "", "evidence_bytes": None}
    notes: list[str] = []
    basis["notes"] = notes
    if source.is_dir():
        limit = min(FOLDER_WALK_LIMIT, max_file_count) if max_file_count > 0 else FOLDER_WALK_LIMIT
        size, entries, complete, stop = _folder_walk(source, limit)
        capped_by_request = not complete and stop == "entries" and 0 < max_file_count <= FOLDER_WALK_LIMIT
        extract_bytes = (min(size, max_extract) if max_extract > 0 else size) if extract else 0
        estimated, method = estimate_from_sizes("folder", evidence_bytes=size, entry_count=entries, extract_bytes=extract_bytes)
        basis.update(evidence_kind="folder", evidence_bytes=size, entry_count=entries, folder_walk_complete=complete or capped_by_request,
                     estimated_bytes=estimated, method=method)
        if capped_by_request:
            notes.append(f"요청의 파일 수 상한({max_file_count:,}개)까지만 셈")
        elif not complete:
            reason = f"{FOLDER_WALK_LIMIT:,}개" if stop == "entries" else f"{FOLDER_WALK_SECONDS:g}초"
            notes.append(f"폴더를 {reason}까지만 세어 하한 값임(실제 출력은 더 클 수 있음)")
        if extract:
            notes.append("추출 켜짐: 대상 분류 파일 복사 바이트(상한)를 더함" + (f", 요청 상한 {format_bytes(max_extract)}" if max_extract > 0 else ""))
        return basis
    if not source.is_file():
        notes.append("증거 경로를 찾지 못함")
        return basis
    from ...core.e01_recorded_hash import (
        EWF2_SIGNATURE,
        discover_segment_files,
        ewf_segment_index,
    )

    suffix = source.suffix.lower()
    is_image = ewf_segment_index(source) is not None or suffix in (".dd", ".raw", ".img", ".bin", ".001")
    if not is_image:
        size = source.stat().st_size
        estimated, method = estimate_from_sizes("file", evidence_bytes=size)
        basis.update(evidence_kind="file", evidence_bytes=size, estimated_bytes=estimated, method=method)
        return basis
    from ...core.e01_native import is_ewf_file, native_extract_file_limit

    try:
        with source.open("rb") as handle:
            ewf2 = handle.read(len(EWF2_SIGNATURE)) == EWF2_SIGNATURE
    except OSError:
        ewf2 = False
    kind = "ewf" if is_ewf_file(source) or ewf2 else "raw"
    segments, gaps = discover_segment_files(source) if kind == "ewf" else ([source], [])
    evidence_bytes = 0
    for segment in segments:
        try:
            evidence_bytes += segment.stat().st_size
        except OSError:
            continue
    media, partition, note = _image_partition(source, segments, kind, partition_start_sector)
    estimated, method = estimate_from_sizes(kind, evidence_bytes=evidence_bytes, media_bytes=media, partition_bytes=partition)
    basis.update(evidence_kind=kind, evidence_bytes=evidence_bytes, segment_count=len(segments), media_bytes=media,
                 partition_bytes=partition, estimated_bytes=estimated, method=method)
    if note:
        notes.append(note)
    if gaps:
        notes.append(f"빠진 세그먼트 번호 {', '.join(str(item) for item in gaps[:16])}")
    notes.append(f"엔진은 이미지당 파일 {native_extract_file_limit():,}개까지만 복사함(파일이 많으면 실제 출력은 더 작음)")
    return basis


def estimate_output_bytes(
    root: Path | str,
    *,
    partition_start_sector: int | None = None,
    max_file_count: int = 0,
    extract: bool = False,
    max_extract_size_bytes: int = 0,
) -> dict[str, object]:
    """The estimate and how it was made: ``{estimated_bytes, method, evidence_kind, evidence_bytes, notes, …}``.

    Cached for :data:`CACHE_SECONDS` per ``(path, size, mtime, options)``."""
    source = Path(root).expanduser()
    try:
        stat = source.stat()
        key: tuple[object, ...] | None = (str(source), stat.st_size, stat.st_mtime_ns, partition_start_sector, max_file_count, extract, max_extract_size_bytes)
    except OSError:
        key = None
    now = time.monotonic()
    if key is not None:
        with _cache_lock:
            hit = _cache.get(key)
        if hit is not None and now - hit[0] < CACHE_SECONDS:
            return {**hit[1], "notes": list(hit[1]["notes"]), "cached": True}  # type: ignore[call-overload]
    basis = _evidence_basis(source, partition_start_sector, max(0, max_file_count), extract, max(0, max_extract_size_bytes))
    if key is not None:
        with _cache_lock:
            if len(_cache) > 64:
                _cache.clear()
            _cache[key] = (now, {**basis, "notes": list(basis["notes"])})  # type: ignore[call-overload]
    return basis


def _free_bytes(output_dir: Path, disk_usage: DiskUsage) -> tuple[int | None, str]:
    """Free bytes of the volume that will hold ``output_dir`` (nearest existing ancestor)."""
    probe = output_dir.expanduser()
    for _ in range(64):
        if probe.exists():
            break
        if probe.parent == probe:
            break
        probe = probe.parent
    try:
        return int(disk_usage(str(probe)).free), str(probe)
    except OSError:
        return None, str(probe)


def space_verdict(estimated: int | None, free: int | None, method: str = "") -> dict[str, object]:
    """``{ok, level, code, message}`` (Korean) for an estimate, its method and a free-space reading.

    The message always says the size is an estimate and names its basis; ``block`` only for a
    reliable upper bound (:data:`RELIABLE_UPPER_BOUND`)."""
    if estimated is None or free is None:
        missing = "예상 출력 크기" if estimated is None else "출력 위치의 여유 공간"
        return {
            "ok": True,
            "level": "unknown",
            "code": None,
            "message": f"{missing}을(를) 확인하지 못해 디스크 여유를 점검하지 않았습니다. 처리 중 공간이 부족하면 런이 실패할 수 있습니다",
        }
    basis = METHOD_BASIS_KO.get(method, "기준 미상")
    estimate_text = f"예상 출력 크기 {format_bytes(estimated)}(추정 — 기준: {basis})"
    high = int(estimated * (1.0 + ESTIMATE_MARGIN))
    if free < estimated and method in RELIABLE_UPPER_BOUND:
        return {
            "ok": False,
            "level": "block",
            "code": DISK_SPACE_INSUFFICIENT,
            "message": (
                f"출력 위치의 여유 공간({format_bytes(free)})이 최대 출력 크기({format_bytes(estimated)}, 기준: {basis})보다 작습니다. "
                "실제 출력은 할당된 데이터만큼이라 더 작을 수 있지만, 부족하면 처리 중 런이 실패합니다. 런은 시작됩니다(경고만)"
            ),
        }
    if free < estimated and method in UNKNOWN_WHEN_SHORT:
        return {
            "ok": True,
            "level": "unknown",
            "code": DISK_SPACE_LOW,
            "message": (
                f"여유 공간({format_bytes(free)})이 {estimate_text}보다 작지만, 이 기준으로는 실제 출력 크기를 알 수 없습니다"
                " (압축하지 않았거나 압축되지 않는 이미지일 수 있음). 처리 중 공간이 부족하면 런이 실패할 수 있습니다"
            ),
        }
    if free < high:
        return {
            "ok": True,
            "level": "warn",
            "code": DISK_SPACE_LOW,
            "message": (
                f"출력 위치의 여유 공간({format_bytes(free)})이 부족할 수 있습니다. {estimate_text}이고 "
                f"오차(±{int(ESTIMATE_MARGIN * 100)}%)를 고려하면 {format_bytes(high)}까지 필요할 수 있습니다. 런은 시작됩니다(경고만)"
            ),
        }
    return {
        "ok": True,
        "level": "ok",
        "code": None,
        "message": f"여유 공간 {format_bytes(free)} — {estimate_text}의 오차(±{int(ESTIMATE_MARGIN * 100)}%)까지 담을 수 있을 것으로 보입니다",
    }


def check_output_space(
    root: Path | str,
    output_dir: Path | str,
    *,
    partition_start_sector: int | None = None,
    disk_usage: DiskUsage | None = None,
    max_file_count: int = 0,
    extract: bool = False,
    max_extract_size_bytes: int = 0,
    resume: bool = False,
    overwrite: bool = False,
) -> dict[str, object]:
    """``{estimated_bytes, free_bytes, ok, level, code, message, basis}`` for a run about to start.

    An empty ``output_dir`` (not chosen yet) gives ``free_bytes=None`` and ``level="unknown"``. A resumed
    or overwriting run reuses / replaces what the folder already holds: ``block`` drops to ``warn``."""
    basis = estimate_output_bytes(
        root, partition_start_sector=partition_start_sector, max_file_count=max_file_count,
        extract=extract, max_extract_size_bytes=max_extract_size_bytes,
    )
    estimated = basis.get("estimated_bytes")
    estimated = estimated if isinstance(estimated, int) else None
    free: int | None = None
    volume = ""
    if str(output_dir).strip():
        free, volume = _free_bytes(Path(output_dir), disk_usage or shutil.disk_usage)
    basis["output_volume_probe"] = volume
    basis["margin"] = ESTIMATE_MARGIN
    basis["estimate_is_upper_bound"] = basis.get("method") in RELIABLE_UPPER_BOUND
    verdict = space_verdict(estimated, free, str(basis.get("method") or ""))
    notes = basis["notes"] if isinstance(basis.get("notes"), list) else []
    if resume or overwrite:
        notes.append("이어서 실행·덮어쓰기: 출력 폴더에 이미 있는 내용은 다시 쓰거나 대체하므로 실제 추가 필요량은 더 작을 수 있음")  # type: ignore[union-attr]
        if verdict["level"] == "block":
            verdict = {**verdict, "ok": True, "level": "warn", "code": DISK_SPACE_LOW}
    if notes and verdict["level"] in ("warn", "block"):
        verdict = {**verdict, "message": f"{verdict['message']} · 참고: {' · '.join(str(item) for item in notes)}"}
    return {"estimated_bytes": estimated, "free_bytes": free, **verdict, "basis": basis}


def preflight_space_for(request: Any, *, root: str | None = None, output_dir: str | None = None) -> dict[str, object] | None:
    """:func:`check_output_space` for a run body or a stored run request (``POST /api/runs``, the case
    run, the retry); ``None`` for a dry run. Advice only: an error in the check is reported as
    ``level="unknown"``, never raised into the run start."""
    if getattr(request, "dry_run", False):
        return None
    try:
        return check_output_space(
            root if root is not None else str(getattr(request, "root", "") or ""),
            output_dir if output_dir is not None else str(getattr(request, "output_dir", "") or ""),
            partition_start_sector=getattr(request, "e01_partition_start_sector", None),
            max_file_count=int(getattr(request, "max_file_count", 0) or 0),
            extract=bool(getattr(request, "extract", False)),
            max_extract_size_bytes=int(getattr(request, "max_extract_size_bytes", 0) or 0),
            resume=bool(getattr(request, "resume", False)),
            overwrite=bool(getattr(request, "overwrite", False)),
        )
    except Exception as exc:  # advice only: never fail a run start
        return {
            "estimated_bytes": None, "free_bytes": None, **space_verdict(None, None),
            "basis": {"notes": [f"디스크 여유 점검 중 오류: {type(exc).__name__}"]},
        }
