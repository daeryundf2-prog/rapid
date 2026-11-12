"""Disk free-space check before a run starts (R8 T-186, GAP-183·278 / IS-160).

:func:`check_output_space` estimates how many bytes a run will write for an evidence and compares
that with the free space of the volume that will hold the output folder (``shutil.disk_usage``).
The answer is ``{estimated_bytes, free_bytes, ok, level, code, message, basis}``:

* ``level="ok"``    -- free space covers the estimate plus its error margin (:data:`ESTIMATE_MARGIN`).
* ``level="warn"``  -- free space covers the estimate but not the margin (``code`` DISK_SPACE_LOW).
* ``level="block"`` -- free space is below the estimate itself (``ok=False``, DISK_SPACE_INSUFFICIENT);
  ``POST /api/runs`` refuses such a run with 507 unless the body sets ``allow_low_disk_space``.
* ``level="unknown"`` -- no estimate or no free-space reading; never blocks.

The estimate model (read only, metadata only — no evidence content is read beyond the partition table):

* E01/Ex01: today's engine copies the selected partition's allocated files into the output
  (IMG-B: 64.1 GB tree of 71.6 GB output). Allocated bytes are unknown before the run, so they are
  approximated from the **compressed segment bytes** (empty sectors compress to almost nothing) times
  :data:`EWF_EXPANSION`, scaled by the selected partition's share of the media and capped at the
  partition size. :data:`EWF_EXPANSION` is calibrated on one real image (IMG-B, R8 QA): segments
  18.5 GB → allocated 64 GB. It is an estimate (±30% target), stated as such in ``basis``.
* raw/dd images: no compression signal, so the selected partition size is the (upper-bound) estimate.
* other evidence files (VHD/VMDK, archives): the file size.
* folders: nothing is copied; the output is the derived rows (:data:`OUTPUT_OVERHEAD` of the folder
  bytes, measured by a bounded walk).

Every estimate adds :data:`OUTPUT_OVERHEAD` (JSONL rows, indexes, case DB: IMG-B 7.5 GB over a
64.1 GB tree).
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

__all__ = [
    "DISK_SPACE_INSUFFICIENT",
    "DISK_SPACE_LOW",
    "ESTIMATE_MARGIN",
    "EWF_EXPANSION",
    "OUTPUT_OVERHEAD",
    "check_output_space",
    "estimate_from_sizes",
    "estimate_output_bytes",
    "format_bytes",
    "space_verdict",
]

DISK_SPACE_LOW = "DISK_SPACE_LOW"
DISK_SPACE_INSUFFICIENT = "DISK_SPACE_INSUFFICIENT"

#: Allocated bytes per compressed EWF segment byte (IMG-B: 64.1 GB tree / 18.5 GB segments ≈ 3.46).
EWF_EXPANSION = 3.5
#: Output bytes beyond the copied files, as a share of them (IMG-B: (71.6 - 64.1) / 64.1 ≈ 0.117).
OUTPUT_OVERHEAD = 0.12
#: The estimate's error target (±30%): free space below ``estimate × (1 + margin)`` is a warning.
ESTIMATE_MARGIN = 0.30
#: Bounded folder walk: entries visited before the folder size is reported as a lower bound.
FOLDER_WALK_LIMIT = 200_000

DiskUsage = Callable[[str], Any]


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
) -> tuple[int, str]:
    """``(estimated output bytes, method)`` from sizes alone (pure; the model of the module docstring)."""
    evidence_bytes = max(0, int(evidence_bytes))
    if kind == "ewf":
        share = 1.0
        if media_bytes and partition_bytes and media_bytes > 0:
            share = min(1.0, max(0.0, partition_bytes / media_bytes))
        copied = evidence_bytes * EWF_EXPANSION * share
        method = "ewf-compressed-segments"
        if partition_bytes:
            copied = min(copied, float(partition_bytes))
        else:
            method = "ewf-compressed-segments-no-partition"
    elif kind == "raw":
        copied = float(partition_bytes or media_bytes or evidence_bytes)
        method = "raw-partition-upper-bound"
    elif kind == "folder":
        return int(evidence_bytes * OUTPUT_OVERHEAD), "folder-derived-rows"
    else:
        copied = float(evidence_bytes)
        method = "evidence-file-size"
    return int(copied * (1.0 + OUTPUT_OVERHEAD)), method


def _folder_bytes(root: Path) -> tuple[int, bool]:
    """``(bytes, complete)`` of a folder; stops after :data:`FOLDER_WALK_LIMIT` entries (lower bound)."""
    total = seen = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    seen += 1
                    if seen > FOLDER_WALK_LIMIT:
                        return total, False
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total, True


def _image_partition(image: Path, start_sector: int | None) -> tuple[str, int | None, int | None, str]:
    """``(kind, media_bytes, selected partition bytes, note)`` from the partition table (read only)."""
    from ...core.e01_native import (
        NativeImageError,
        is_ewf_file,
        native_partition_table,
        open_image_media,
        select_native_partition,
    )

    kind = "ewf" if is_ewf_file(image) else "raw"
    try:
        with open_image_media(image) as (handle, _media_kind):
            media = int(handle.get_media_size())
            partitions, _sector_size = native_partition_table(handle)
    except (NativeImageError, OSError, ValueError, RuntimeError) as exc:
        return kind, None, None, f"파티션 표를 읽지 못함: {str(exc)[:160]}"
    try:
        selected = select_native_partition(partitions, preferred_start_sector=start_sector)
    except ValueError as exc:
        return kind, media, None, f"선택 파티션을 찾지 못함: {str(exc)[:160]}"
    for row in partitions:
        if selected is not None and int(row.get("start_sector") or 0) == selected:
            size = int(row.get("size_bytes") or 0) or int(row.get("sector_count") or 0) * int(row.get("sector_size_bytes") or 512)
            return kind, media, size or None, ""
    return kind, media, None, "지원하는 파일 시스템 파티션이 없음"


def estimate_output_bytes(root: Path | str, *, partition_start_sector: int | None = None) -> dict[str, object]:
    """The estimate and how it was made: ``{estimated_bytes, method, evidence_kind, evidence_bytes, …}``."""
    source = Path(root).expanduser()
    basis: dict[str, object] = {"estimated_bytes": None, "method": "", "evidence_kind": "", "evidence_bytes": None}
    if source.is_dir():
        size, complete = _folder_bytes(source)
        estimated, method = estimate_from_sizes("folder", evidence_bytes=size)
        basis.update(evidence_kind="folder", evidence_bytes=size, folder_walk_complete=complete, estimated_bytes=estimated, method=method)
        if not complete:
            basis["note"] = f"폴더 항목이 {FOLDER_WALK_LIMIT:,}개를 넘어 일부만 세었음(하한)"
        return basis
    if not source.is_file():
        basis["note"] = "증거 경로를 찾지 못함"
        return basis
    from ...core.e01 import discover_e01_segments, ewf_segment_number

    suffix = source.suffix.lower()
    is_image = ewf_segment_number(source) is not None or suffix in (".dd", ".raw", ".img", ".bin", ".001")
    if not is_image:
        size = source.stat().st_size
        estimated, method = estimate_from_sizes("file", evidence_bytes=size)
        basis.update(evidence_kind="file", evidence_bytes=size, estimated_bytes=estimated, method=method)
        return basis
    kind, media, partition, note = _image_partition(source, partition_start_sector)
    segments = discover_e01_segments(source) if kind == "ewf" else [source]
    evidence_bytes = 0
    for segment in segments:
        try:
            evidence_bytes += segment.stat().st_size
        except OSError:
            continue
    estimated, method = estimate_from_sizes(kind, evidence_bytes=evidence_bytes, media_bytes=media, partition_bytes=partition)
    basis.update(
        evidence_kind=kind,
        evidence_bytes=evidence_bytes,
        segment_count=len(segments),
        media_bytes=media,
        partition_bytes=partition,
        estimated_bytes=estimated,
        method=method,
    )
    if note:
        basis["note"] = note
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


def space_verdict(estimated: int | None, free: int | None) -> dict[str, object]:
    """``{ok, level, code, message}`` (Korean) for an estimate and a free-space reading."""
    if estimated is None or free is None:
        missing = "예상 출력 크기" if estimated is None else "출력 위치의 여유 공간"
        return {
            "ok": True,
            "level": "unknown",
            "code": None,
            "message": f"{missing}을(를) 확인하지 못해 디스크 여유를 점검하지 않았습니다. 처리 중 공간이 부족하면 런이 실패할 수 있습니다",
        }
    high = int(estimated * (1.0 + ESTIMATE_MARGIN))
    if free < estimated:
        return {
            "ok": False,
            "level": "block",
            "code": DISK_SPACE_INSUFFICIENT,
            "message": (
                f"출력 위치의 여유 공간({format_bytes(free)})이 예상 출력 크기({format_bytes(estimated)})보다 작습니다. "
                f"처리 중 공간이 부족해 런이 실패할 수 있습니다. 여유가 {format_bytes(high)} 이상인 출력 위치를 지정하세요"
            ),
        }
    if free < high:
        return {
            "ok": True,
            "level": "warn",
            "code": DISK_SPACE_LOW,
            "message": (
                f"출력 위치의 여유 공간({format_bytes(free)})이 빠듯합니다. 예상 출력 크기는 {format_bytes(estimated)}이고 "
                f"오차(±{int(ESTIMATE_MARGIN * 100)}%)를 고려하면 {format_bytes(high)}까지 필요할 수 있습니다"
            ),
        }
    return {
        "ok": True,
        "level": "ok",
        "code": None,
        "message": f"여유 공간 {format_bytes(free)} — 예상 출력 크기 {format_bytes(estimated)}(±{int(ESTIMATE_MARGIN * 100)}%)를 담을 수 있습니다",
    }


def check_output_space(
    root: Path | str,
    output_dir: Path | str,
    *,
    partition_start_sector: int | None = None,
    disk_usage: DiskUsage | None = None,
) -> dict[str, object]:
    """``{estimated_bytes, free_bytes, ok, level, code, message, basis}`` for a run about to start.

    An empty ``output_dir`` (not chosen yet) gives ``free_bytes=None`` and ``level="unknown"``."""
    basis = estimate_output_bytes(root, partition_start_sector=partition_start_sector)
    estimated = basis.get("estimated_bytes")
    estimated = estimated if isinstance(estimated, int) else None
    free: int | None = None
    volume = ""
    if str(output_dir).strip():
        free, volume = _free_bytes(Path(output_dir), disk_usage or shutil.disk_usage)
    basis["output_volume_probe"] = volume
    basis["margin"] = ESTIMATE_MARGIN
    return {"estimated_bytes": estimated, "free_bytes": free, **space_verdict(estimated, free), "basis": basis}
