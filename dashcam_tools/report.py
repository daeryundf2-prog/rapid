#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

RENAME_HELPER_IMPORT_ERROR = ""

try:
    # Reuse renamer internals for consistency
    from ._rename_impl import (
        VENDOR_PROFILES,
        best_guess_time,
        get_file_times,
        get_duration_ffprobe,
    )
except Exception as exc:
    RENAME_HELPER_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
    VENDOR_PROFILES = {}
    def best_guess_time(path, profile, use_metadata_first=True, prefer_start_from_filetime=False):
        return (None, "none")
    def get_file_times(path):
        try:
            st = os.stat(path)
            birth = getattr(st, "st_birthtime", None)
            return (dt.datetime.fromtimestamp(birth) if birth else None, dt.datetime.fromtimestamp(st.st_mtime))
        except Exception:
            return (None, None)
    def get_duration_ffprobe(path):
        return 0.0

VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".mts", ".m2ts", ".ts"}


def iter_videos(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in VIDEO_EXTS:
            yield root
        return
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if p.suffix.lower() in VIDEO_EXTS:
                yield p


def compute_hash(path: Path, algo: str = "sha256", chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def tool_version(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
        first = out.splitlines()[0].strip()
        return first
    except Exception:
        return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate forensic timeline/report for dashcam videos")
    ap.add_argument("--dir", required=True, help="Target directory or file")
    ap.add_argument("--profile", default="generic", choices=sorted(VENDOR_PROFILES.keys()) if VENDOR_PROFILES else ["generic"], help="ROI profile for OCR if enabled")
    ap.add_argument("--no-ocr", action="store_true", help="Skip OCR-derived overlay start time")
    ap.add_argument("--prefer-start", action="store_true", help="Use duration to estimate clip start time for file times")
    ap.add_argument("--hash", choices=["sha256","sha1","md5"], default=None, help="Compute hash for each file")
    ap.add_argument("--csv", default="timeline.csv", help="Timeline CSV output path")
    ap.add_argument("--json", default="timeline.json", help="JSON summary output path")
    ap.add_argument("--bodyfile", default="", help="Optional Sleuth Kit bodyfile output path")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of files (0=all)")
    args = ap.parse_args(argv)

    root = Path(args.dir).expanduser().resolve()
    out_csv = Path(args.csv).expanduser()
    out_json = Path(args.json).expanduser()
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    bf_path = Path(args.bodyfile).expanduser() if args.bodyfile else None
    if bf_path:
        bf_path.parent.mkdir(parents=True, exist_ok=True)

    profile = VENDOR_PROFILES.get(args.profile) if VENDOR_PROFILES else None

    rows: List[Dict[str, object]] = []
    errors: List[Dict[str, str]] = []
    total = 0

    for p in iter_videos(root):
        if args.limit and total >= args.limit:
            break
        total += 1
        size = None
        try:
            stat = p.stat()
            size = stat.st_size
        except OSError as exc:
            errors.append({"path": str(p), "stage": "stat", "error": f"{type(exc).__name__}: {exc}"})

        # Filesystem times
        btime, mtime = get_file_times(p)
        # Metadata/overlay decisions
        decided, method = best_guess_time(p, profile, use_metadata_first=True, prefer_start_from_filetime=args.prefer_start) if profile else (None, "none")
        overlay = None
        if not getattr(args, 'no_ocr', False) and profile:
            # Derive overlay start by forcing OCR path only
            ocr_decided, mth = best_guess_time(p, profile, use_metadata_first=False, prefer_start_from_filetime=False)
            if mth == "ocr":
                overlay = ocr_decided
        meta_time = None
        if method == "metadata":
            meta_time = decided
        # Hash
        hval = None
        if args.hash:
            try:
                hval = compute_hash(p, args.hash)
            except OSError as exc:
                errors.append({"path": str(p), "stage": "hash", "error": f"{type(exc).__name__}: {exc}"})
                hval = None

        # Emit events
        def add_event(ts: Optional[dt.datetime], etype: str, source: str):
            if ts is None:
                return
            rows.append({
                "time": ts.isoformat(),
                "event": etype,
                "source": source,
                "path": str(p),
                "size": size,
                "hash_algo": args.hash or "",
                "hash": hval or "",
            })
        add_event(btime, "file_birth", "filesystem")
        add_event(mtime, "file_mtime", "filesystem")
        add_event(meta_time, "container_creation", "metadata")
        add_event(overlay, "overlay_start", "ocr")
        if decided and method not in ("metadata", "none"):
            add_event(decided, f"decided_{method}", method)

    # Sort by time
    rows.sort(key=lambda r: r.get("time", ""))

    # Write CSV
    with open(out_csv, "w", newline="") as fp:
        wr = csv.DictWriter(fp, fieldnames=["time","event","source","path","size","hash_algo","hash"])
        wr.writeheader()
        wr.writerows(rows)

    # Bodyfile (MACB). Provide minimal records; unknown fields left as 0/-
    if bf_path:
        with open(bf_path, "w", newline="") as bf:
            for r in rows:
                if r["event"] in ("file_mtime","file_birth"):
                    # bodyfile fields: md5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
                    # We only set: md5, name, size, and the matching time; rest 0
                    md5 = r["hash"] if r["hash_algo"] == "md5" else "-"
                    name = r["path"]
                    size = r.get("size") or 0
                    t = r["time"]
                    # Map event to appropriate column
                    atime=mtime=ctime=crtime=0
                    try:
                        ts = int(dt.datetime.fromisoformat(t).timestamp())
                    except (TypeError, ValueError) as exc:
                        errors.append({"path": str(r.get("path") or ""), "stage": "bodyfile-time", "error": f"{type(exc).__name__}: {exc}"})
                        ts = 0
                    if r["event"] == "file_mtime":
                        mtime = ts
                    elif r["event"] == "file_birth":
                        crtime = ts
                    line = f"{md5}|{name}|0|---------|0|0|{size}|{atime}|{mtime}|{ctime}|{crtime}\n"
                    bf.write(line)

    # JSON summary
    env = {
        "tool": "dashcam-tools/report",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "ffprobe": tool_version(["ffprobe","-version"]),
        "tesseract": tool_version(["tesseract","--version"]),
    }
    summary = {
        "total_events": len(rows),
        "total_files": total,
        "error_count": len(errors),
        "hash_algo": args.hash or "",
        "generated_at": dt.datetime.now().isoformat(),
        "env": env,
        "helper_import_error": RENAME_HELPER_IMPORT_ERROR,
        "degraded": bool(RENAME_HELPER_IMPORT_ERROR or errors),
    }
    with open(out_json, "w") as jf:
        json.dump({"summary": summary, "timeline": rows, "errors": errors}, jf, ensure_ascii=False, indent=2)

    print(f"Timeline CSV: {out_csv}")
    if bf_path:
        print(f"Bodyfile: {bf_path}")
    print(f"JSON: {out_json}")
    return 1 if RENAME_HELPER_IMPORT_ERROR else 0

if __name__ == "__main__":
    raise SystemExit(main())
