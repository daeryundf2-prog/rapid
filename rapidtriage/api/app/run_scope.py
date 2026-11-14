"""Processing scope on four axes (R8 T-023, server presentation layer).

A run's coverage is never one number. It is told on four axes:

1. partitions  — how many partitions the image has, how many have a supported
   filesystem, how many this run processed;
2. allocated   — allocated (in-use) files: listed %, content read %;
3. deleted     — deleted MFT file records: how many exist, how many the deleted
   sweep attempted / listed;
4. unallocated — unallocated space scanned % (not measured today).

Everything is derived from what the run already recorded — the native
extraction stats (``files``/``deleted_files``/``deleted_read_errors``/
``truncated``/``errors``/``file_limit``), the partition selection, and the
``$MFT`` copy the native engine dumps next to the stage (record headers only:
signature, in-use/directory flags, base-record reference). Nothing here parses
file content or changes extraction.

The stats cannot tell a truncated allocated walk from a truncated deleted
sweep, so the rule "the sweep only writes while ``files < limit``; if it wrote
anything the allocated walk finished below the cap" is applied and the result
carries ``basis: "inferred"`` until a Sleuth Kit ``fls``/``ils`` comparison
(T-038) or split counters (T-270, then ``basis: "measured"``) confirm it. Runs
without stats (folder evidence, older results) get ``basis: "unavailable"``.

Percentages are floored to one decimal so a value below 100 never reads as 100.
No single "n% processed" field or sentence is produced.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROFILE_VERSION = "rapidtriage-run-scope-v1"
BASIS_INFERRED = "inferred"
BASIS_UNAVAILABLE = "unavailable"
MFT_FILE_NAME = "MFT.bin"
#: Default stage layout: ``<output_dir>/_e01/_system/MFT.bin`` (core/run → core/e01).
MFT_DEFAULT_RELATIVE = Path("_e01") / "_system" / MFT_FILE_NAME
MFT_DEFAULT_RECORD_SIZE = 1024
#: Records per read; slicing per-field over a block keeps a ~1 GB $MFT near one second.
MFT_READ_RECORDS = 16384
MFT_CACHE_MAX = 8

NOTE_INFERRED = (
    "추정: 처리 범위는 추출 통계와 $MFT 사본 머리 집계로 추론한 값입니다. "
    "Sleuth Kit fls·ils 대조 전까지 확정 수치가 아닙니다."
)
NOTE_UNAVAILABLE = "이 결과에는 추출 통계가 없어 처리 범위를 계산하지 않았습니다(폴더 증거 또는 이전 결과)."
NOTE_UNALLOCATED = "비할당 영역은 측정하지 않았습니다."

_mft_cache: dict[tuple[str, int, int], dict[str, int]] = {}


# --- small helpers ------------------------------------------------------------


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _pct(numerator: int | None, denominator: int | None) -> float | None:
    """Floor to one decimal, capped at 100; ``None`` when the denominator is unknown/zero."""
    if numerator is None or not denominator or denominator <= 0:
        return None
    tenths = (max(numerator, 0) * 1000) // denominator
    return min(tenths, 1000) / 10


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _count(value: int) -> str:
    return f"{value:,}"


# --- inputs -------------------------------------------------------------------


def _read_e01_output(summary: Mapping[str, Any], run_dir: Path | None) -> Mapping[str, Any]:
    """The image stage payload when the summary's ``source`` block lacks it (older summaries)."""
    outputs = _mapping(summary.get("outputs"))
    raw = outputs.get("e01")
    if not isinstance(raw, str) or not raw or run_dir is None:
        return {}
    path = Path(raw)
    if not path.is_absolute():
        path = run_dir / path
    try:
        resolved = path.resolve()
        resolved.relative_to(run_dir.resolve())
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _image_source(summary: Mapping[str, Any], run_dir: Path | None) -> Mapping[str, Any]:
    source = _mapping(summary.get("source"))
    manifest = _mapping(source.get("recovered_root_manifest"))
    if source.get("partition_selection") or manifest.get("native_extraction_stats"):
        return source
    return _read_e01_output(summary, run_dir)


def _extraction_stats(source: Mapping[str, Any]) -> dict[str, int] | None:
    manifest = _mapping(source.get("recovered_root_manifest"))
    raw = _mapping(manifest.get("native_extraction_stats"))
    if not raw or _int(raw.get("files")) is None:
        return None
    keys = ("files", "errors", "truncated", "deleted_files", "deleted_read_errors", "file_limit")
    return {key: max(_int(raw.get(key)) or 0, 0) for key in keys}


def _mft_path(source: Mapping[str, Any], run_dir: Path | None) -> Path | None:
    manifest = _mapping(source.get("recovered_root_manifest"))
    recorded = _mapping(manifest.get("system_artifacts")).get("mft")
    candidates: list[Path] = []
    if isinstance(recorded, str) and recorded:
        candidates.append(Path(recorded))
    if run_dir is not None:
        candidates.append(run_dir / MFT_DEFAULT_RELATIVE)
    for candidate in candidates:
        try:
            if candidate.name == MFT_FILE_NAME and candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


# --- $MFT header tally ----------------------------------------------------------


def _mft_record_size(head: bytes) -> int:
    """Allocated record size from record 0 (offset 0x1C), else 1024."""
    if len(head) >= 0x20 and head[:4] == b"FILE":
        size = int.from_bytes(head[0x1C:0x20], "little")
        if 256 <= size <= 65536 and size & (size - 1) == 0:
            return size
    return MFT_DEFAULT_RECORD_SIZE


def tally_mft_headers(path: Path) -> dict[str, int]:
    """Count records by header only: ``FILE`` signature, base vs extension, in-use/directory flags.

    Fixups touch the last two bytes of each sector, so the fields read here
    (offsets 0-3, 22, 32-37) are valid without applying them.
    """
    counts = {
        "records": 0,
        "invalid": 0,
        "extension_records": 0,
        "in_use_files": 0,
        "in_use_dirs": 0,
        "deleted_files": 0,
        "deleted_dirs": 0,
    }
    with path.open("rb") as handle:
        record_size = _mft_record_size(handle.read(0x20))
        handle.seek(0)
        while True:
            block = handle.read(record_size * MFT_READ_RECORDS)
            whole = len(block) // record_size
            if whole == 0:
                break
            block = block[: whole * record_size]
            step = record_size
            signatures = zip(block[0::step], block[1::step], block[2::step], block[3::step])
            bases = zip(*(block[offset::step] for offset in range(32, 38)))
            for signature, base, flags in zip(signatures, bases, block[22::step]):
                counts["records"] += 1
                if signature != (0x46, 0x49, 0x4C, 0x45):  # b"FILE"
                    counts["invalid"] += 1
                elif any(base):
                    counts["extension_records"] += 1
                elif flags & 0x01:
                    counts["in_use_dirs" if flags & 0x02 else "in_use_files"] += 1
                else:
                    counts["deleted_dirs" if flags & 0x02 else "deleted_files"] += 1
    return counts


def cached_mft_tally(path: Path) -> dict[str, int] | None:
    """Header tally keyed by (path, size, mtime); ``None`` when the copy cannot be read."""
    try:
        stat = path.stat()
        key = (os.fspath(path.resolve()), stat.st_size, stat.st_mtime_ns)
    except OSError:
        return None
    cached = _mft_cache.get(key)
    if cached is not None:
        return dict(cached)
    try:
        counts = tally_mft_headers(path)
    except OSError:
        return None
    if len(_mft_cache) >= MFT_CACHE_MAX:
        _mft_cache.pop(next(iter(_mft_cache)))
    _mft_cache[key] = counts
    return dict(counts)


# --- axes -----------------------------------------------------------------------


def _partitions_axis(source: Mapping[str, Any], stats: Mapping[str, int] | None) -> dict[str, int | None]:
    selection = _mapping(source.get("partition_selection"))
    total = _int(selection.get("partition_count"))
    if total is None:
        rows = selection.get("partition_browser_rows") or source.get("partition_table")
        total = len(rows) if isinstance(rows, list) and rows else None
    supported = _int(selection.get("supported_partition_count"))
    selected = _int(selection.get("selected_start_sector"))
    if selected is None:
        selected = _int(source.get("partition_start_sector"))
    # The extraction engines process exactly the one selected partition.
    processed = 1 if (stats is not None or selected is not None) else (0 if total else None)
    return {"total": total, "supported": supported, "processed": processed}


def _unavailable() -> dict[str, Any]:
    return {
        "profile_version": PROFILE_VERSION,
        "basis": BASIS_UNAVAILABLE,
        "partitions": {"total": None, "supported": None, "processed": None},
        "allocated": {"listed_pct": None, "content_pct": None, "basis": BASIS_UNAVAILABLE},
        "deleted": {"records": None, "attempted": None, "attempted_pct": None, "listed_pct": None},
        "unallocated": {"scanned_pct": None, "measured": False},
        "caps": [],
        "mft": None,
        "partial": None,
        "notes": [NOTE_UNAVAILABLE],
    }


def build_run_scope(summary: Mapping[str, Any] | None, run_dir: Path | None) -> dict[str, Any]:
    """Four-axis processing scope for one run (see module docstring)."""
    if not isinstance(summary, Mapping):
        return _unavailable()
    source = _image_source(summary, run_dir)
    stats = _extraction_stats(source)
    if stats is None:
        scope = _unavailable()
        if source.get("partition_selection"):
            scope["partitions"] = _partitions_axis(source, None)
        return scope

    mft_path = _mft_path(source, run_dir)
    mft = cached_mft_tally(mft_path) if mft_path is not None else None
    limit = stats["file_limit"]
    truncated = stats["truncated"]
    attempted = stats["deleted_files"] + stats["deleted_read_errors"]
    # Inference rule: the deleted sweep only touches records while files < limit,
    # so any sweep activity means the allocated walk ended below the cap.
    walk_complete = truncated == 0 or attempted > 0
    allocated_copies = max(stats["files"] - stats["deleted_files"], 0)
    allocated_errors = max(stats["errors"] - stats["deleted_read_errors"], 0)
    notes: list[str] = [NOTE_INFERRED]

    partitions = _partitions_axis(source, stats)
    if partitions["supported"] and partitions["processed"] is not None and partitions["processed"] < partitions["supported"]:
        notes.append(
            f"지원 파일시스템 파티션 {partitions['supported']}개 중 {partitions['processed']}개만 처리했습니다."
        )

    allocated: dict[str, Any] = {
        "listed_pct": 100.0 if walk_complete else None,
        "content_pct": _pct(allocated_copies, allocated_copies + allocated_errors) if walk_complete else None,
        "basis": BASIS_INFERRED,
        "records": mft["in_use_files"] if mft else None,
        "copies": allocated_copies,
        "read_errors": allocated_errors,
    }
    if walk_complete and truncated:
        notes.append(
            f"삭제 레코드 정리가 파일을 기록했으므로 할당 파일 순회는 추출 상한({_count(limit)}개)에 "
            "닿지 않은 것으로 추론했습니다."
        )
    elif not walk_complete:
        notes.append(
            f"추출 상한({_count(limit)}개)에 닿아 할당 파일 순회가 잘렸을 수 있습니다. "
            "할당 파일 목록화 비율은 계산하지 않았습니다."
        )
    if allocated_errors:
        notes.append(f"할당 영역 읽기 오류 {_count(allocated_errors)}건(디렉터리 목록 실패 포함 가능).")

    # Deleted records: the $MFT header count (base, non-directory, not in use) when the
    # copy exists; otherwise the sweep's own candidate count when the walk finished.
    if mft is not None:
        records: int | None = mft["deleted_files"]
        records_source = "mft_header"
    elif walk_complete:
        records = attempted + truncated
        records_source = "extraction_stats"
    else:
        records, records_source = None, None
    deleted = {
        "records": records,
        "records_source": records_source,
        "attempted": attempted,
        "attempted_pct": _pct(attempted, records),
        "listed": stats["deleted_files"],
        "listed_pct": _pct(stats["deleted_files"], records),
        "not_attempted": truncated if walk_complete else None,
        "read_errors": stats["deleted_read_errors"],
        "directories": mft["deleted_dirs"] if mft else None,
    }
    if walk_complete and truncated:
        notes.append(
            f"추출 상한({_count(limit)}개)에 닿아 삭제 레코드 {_count(truncated)}건은 내용 추출을 시도하지 않았습니다."
        )
    if mft and mft["deleted_dirs"]:
        notes.append(f"삭제된 디렉터리 레코드 {_count(mft['deleted_dirs'])}건은 파일 목록에 없습니다.")
    notes.append(NOTE_UNALLOCATED)

    caps: list[dict[str, Any]] = []
    if truncated:
        caps.append(
            {
                "code": "native_extract_file_limit",
                "limit": limit,
                "reached": True,
                "skipped": truncated,
                "axis": "deleted" if walk_complete else "unknown",
            }
        )

    known = [allocated["listed_pct"], allocated["content_pct"], deleted["attempted_pct"]]
    partial = bool(caps) or any(value is not None and value < 100 for value in known)
    if partitions["supported"] and partitions["processed"] is not None:
        partial = partial or partitions["processed"] < partitions["supported"]

    return {
        "profile_version": PROFILE_VERSION,
        "basis": BASIS_INFERRED,
        "partitions": partitions,
        "allocated": allocated,
        "deleted": deleted,
        "unallocated": {"scanned_pct": None, "measured": False},
        "caps": caps,
        "mft": mft,
        "partial": partial,
        "notes": notes,
    }
