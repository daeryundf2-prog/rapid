#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/r8-recovery-diff.py --image <image.E01> --run-dir <rapid run/extraction dir> \
#       [--max-entries N] --output <report.json>
#
# Independent reference diff: opens the E01 with pyewf + pytsk3 (not the rapid
# engine), enumerates every partition, walks each filesystem for allocated vs
# deleted regular files, and compares normalized paths with the files found
# under --run-dir. Output schema r8-recovery-diff-v1 holds COUNTS ONLY (no
# paths). Exit 0 = every partition ok, 2 = at least one unsupported/error.
# Engineering measurement; not release evidence.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.extraction_failures import (
    iter_extracted_files,
    normalize_relative_key,
)

SCHEMA_VERSION = "r8-recovery-diff-v1"
# Filesystem roots inside a run dir: native engine (_e01/fs, multi-partition _e01/fs/p<N>) and the
# Sleuth Kit tsk_recover layout (_e01/filesystem). Everything else in a run dir is run output.
RUN_PREFIXES = ("_e01/fs", "_e01/filesystem")
_PARTITION_DIR = re.compile(r"^p\d+/")


def strip_run_prefix(relative: str) -> str:
    """Path inside the extracted filesystem, or "" when the entry is not extracted file content."""
    path = relative.replace("\\", "/").strip("/")
    lowered = path.lower()
    for prefix in RUN_PREFIXES:
        if lowered.startswith(prefix + "/"):
            inner = path[len(prefix) + 1 :]
            return _PARTITION_DIR.sub("", inner, count=1)
    return ""


def rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def match_entries(
    ref_allocated: Iterable[str],
    ref_deleted: Iterable[str],
    rapid_paths: Iterable[str],
) -> dict[str, int | float | None]:
    """Pure matching of reference vs rapid paths (all normalized via normalize_relative_key)."""
    alloc = {normalize_relative_key(p) for p in ref_allocated}
    deleted = {normalize_relative_key(p) for p in ref_deleted} - alloc
    rapid = {normalize_relative_key(p) for p in rapid_paths}
    alloc_matched = len(alloc & rapid)
    deleted_matched = len(deleted & rapid)
    return {
        "ref_allocated": len(alloc),
        "ref_deleted": len(deleted),
        "rapid_allocated_matched": alloc_matched,
        "rapid_deleted_matched": deleted_matched,
        "allocated_recall": rate(alloc_matched, len(alloc)),
        "deleted_recall": rate(deleted_matched, len(deleted)),
        "rapid_only": len(rapid - alloc - deleted),
    }


def load_rapid_paths(run_dir: Path) -> list[str]:
    paths = []
    for item in iter_extracted_files(run_dir):
        stripped = strip_run_prefix(item.relative_path)
        if stripped:
            paths.append(rapid_key(stripped))
    return paths


def deleted_key(address: int) -> str:
    """Deleted entries are matched by metadata address (MFT record / inode), not by path:
    rapid writes them as _deleted_mft/<addr>-<name> or _deleted/.../<addr>-<name>."""
    return f"#deleted/{int(address)}"


_RAPID_DELETED = re.compile(r"^(?:_deleted_mft|_deleted)/(?:.*/)?(\d+)-[^/]*$")


def rapid_key(path: str) -> str:
    match = _RAPID_DELETED.match(path.replace("\\", "/"))
    return deleted_key(int(match.group(1))) if match else path


def walk_filesystem(
    fs, max_entries: int | None, counters: dict[str, int] | None = None
) -> tuple[list[str], list[str]]:
    """Return (allocated paths, deleted address keys) of regular files; loop-guarded by inode.

    Deleted names whose metadata is gone (meta is None) cannot be recovered by any tool; they are
    counted in counters["ref_deleted_name_only"] instead of the recall denominator."""
    import pytsk3

    allocated: list[str] = []
    deleted: list[str] = []
    seen_dirs: set[int] = set()
    root = fs.open_dir(path="/")
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        for entry in directory:
            name_info = entry.info.name
            meta = entry.info.meta
            if name_info is None:
                continue
            if meta is None:
                if counters is not None and int(name_info.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                    counters["ref_deleted_name_only"] = counters.get("ref_deleted_name_only", 0) + 1
                continue
            name = name_info.name.decode("utf-8", errors="replace")
            if name in (".", ".."):
                continue
            path = f"{prefix}/{name}"
            is_deleted = bool(
                (int(name_info.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                or (int(meta.flags) & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            )
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                if meta.addr in seen_dirs:
                    continue
                seen_dirs.add(meta.addr)
                try:
                    stack.append((fs.open_dir(inode=meta.addr), path))
                except OSError:
                    pass
            elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                if is_deleted:
                    deleted.append(deleted_key(meta.addr))
                else:
                    allocated.append(path)
            if max_entries is not None and len(allocated) + len(deleted) >= max_entries:
                return allocated, deleted
    return allocated, deleted


def open_image(image: Path):
    import pyewf
    import pytsk3

    handle = pyewf.handle()
    handle.open(pyewf.glob(str(image)))

    class EwfImgInfo(pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self):
            return self._ewf_handle.get_media_size()

    return EwfImgInfo(handle)


def enumerate_partitions(img) -> list[tuple[int, int, int]]:
    """Return [(index, start_sector, byte_offset)]; whole image at offset 0 if no volume system."""
    import pytsk3

    try:
        volume = pytsk3.Volume_Info(img)
    except OSError:
        return [(0, 0, 0)]
    block_size = int(volume.info.block_size)
    result = []
    for part in volume:
        if not (int(part.flags) & pytsk3.TSK_VS_PART_FLAG_ALLOC):
            continue
        result.append((int(part.addr), int(part.start), int(part.start) * block_size))
    return result


def diff_partition(img, index: int, start_sector: int, offset: int, rapid_paths: list[str], max_entries: int | None):
    import pytsk3

    row: dict[str, object] = {"index": index, "start_sector": start_sector, "fs_type": None}
    try:
        fs = pytsk3.FS_Info(img, offset=offset)
    except OSError as exc:
        row.update(status="unsupported", error_kind=type(exc).__name__)
        return row
    try:
        row["fs_type"] = str(fs.info.ftype).rsplit("_", 1)[-1].lower().removeprefix("tsk_fs_type_")
        counters: dict[str, int] = {"ref_deleted_name_only": 0}
        allocated, deleted = walk_filesystem(fs, max_entries, counters)
        row.update(match_entries(allocated, deleted, rapid_paths))
        row.update(counters)
        row["status"] = "ok"
    except Exception as exc:
        row.update(status="error", error_kind=type(exc).__name__)
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pytsk3 reference recovery diff (counts only)")
    parser.add_argument("--image", required=True, type=Path, help="first E01 segment")
    parser.add_argument("--run-dir", required=True, type=Path, help="rapid run/extraction directory")
    parser.add_argument("--max-entries", type=int, default=None, help="stop each partition walk after N file entries")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    rapid_paths = load_rapid_paths(args.run_dir)
    partitions: list[dict[str, object]] = []
    img = open_image(args.image)
    try:
        for index, start, offset in enumerate_partitions(img):
            partitions.append(diff_partition(img, index, start, offset, rapid_paths, args.max_entries))
    finally:
        img.close()
    report = {
        "schema_version": SCHEMA_VERSION,
        "release_evidence_status": "engineering_check_only",
        "max_entries": args.max_entries,
        "rapid_files": len(rapid_paths),
        "partitions": partitions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{len(partitions)} partition(s) -> {args.output}")
    return 0 if all(p["status"] == "ok" for p in partitions) else 2


if __name__ == "__main__":
    raise SystemExit(main())
