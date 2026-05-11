#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Packaged ingest CLI (dashcam-ingest)."""
from __future__ import annotations
import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".mts", ".m2ts", ".ts"}


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def rsync_copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    cmd = ["rsync", "-a", "--ignore-existing", "--times", f"{src}/", f"{dst}/"]
    try:
        completed = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"rsync failed for {src} -> {dst}: {type(exc).__name__}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "rsync failed").strip()
        raise RuntimeError(f"rsync failed for {src} -> {dst}: {detail}")


def run_unmount_command(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, check=False)
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=f"{type(exc).__name__}: {exc}")


def ensure_tools_or_warn() -> None:
    missing = []
    for c in ("ewfmount", "mmls", "tsk_recover"):
        if not have(c):
            missing.append(c)
    if missing:
        print("[warn] E01 support is limited: missing tools:", ", ".join(missing))
        if sys.platform == "darwin":
            print("       Install via: brew install libewf sleuthkit")
        elif sys.platform.startswith("linux"):
            print("       Install via: sudo apt-get install libewf-dev sleuthkit")


def mmls_first_filesystem(raw_path: Path) -> Optional[int]:
    try:
        out = subprocess.check_output(["mmls", str(raw_path)], stderr=subprocess.STDOUT)
        text = out.decode("utf-8", errors="ignore")
    except Exception:
        return None
    best_start = None
    best_size = -1
    for line in text.splitlines():
        m = re.search(r"^\s*\d+:\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if not m:
            continue
        start = int(m.group(1)); size = int(m.group(2)); desc = m.group(3).lower()
        if any(k in desc for k in ("fat", "exfat", "ntfs", "basic data", "msdos")):
            if size > best_size:
                best_size = size; best_start = start
    return best_start


def extract_from_e01(e01: Path, stage_dir: Path) -> Optional[Path]:
    stage_dir.mkdir(parents=True, exist_ok=True)
    if not have("ewfmount") or not have("mmls") or not have("tsk_recover"):
        ensure_tools_or_warn(); return None
    mount_dir = stage_dir / "_ewfmount"; raw_img = mount_dir / "ewf1"
    try:
        mount_dir.mkdir(parents=True, exist_ok=True)
        p = subprocess.run(["ewfmount", str(e01), str(mount_dir)], capture_output=True, text=True)
        if p.returncode != 0 or not raw_img.exists():
            print(f"[error] ewfmount failed for {e01}: {p.stderr.strip()}"); return None
        start = mmls_first_filesystem(raw_img)
        if start is None:
            print(f"[error] mmls could not find a FAT/exFAT/NTFS partition in {e01}"); return None
        extract_dir = stage_dir / "_extract"; extract_dir.mkdir(parents=True, exist_ok=True)
        rec = subprocess.run(["tsk_recover", "-e", "-a", "-o", str(start), str(raw_img), str(extract_dir)], capture_output=True, text=True)
        if rec.returncode != 0:
            print(f"[error] tsk_recover failed: {rec.stderr.strip()}"); return None
        return extract_dir
    finally:
        if mount_dir.exists():
            unmount_results = [
                run_unmount_command(["umount", str(mount_dir)]),
                run_unmount_command(["fusermount", "-u", str(mount_dir)]),
            ]
            if all(result.returncode != 0 for result in unmount_results):
                messages = "; ".join((result.stderr or result.stdout or "unmount failed").strip() for result in unmount_results)
                print(f"[warn] cleanup failed for mount {mount_dir}: {messages}", file=sys.stderr)


def collect_videos(src_root: Path, dest_root: Path) -> int:
    count = 0
    for dirpath, _, files in os.walk(src_root):
        for name in files:
            p = Path(dirpath) / name
            if p.suffix.lower() in VIDEO_EXTS:
                rel = p.relative_to(src_root)
                dst = dest_root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(p, dst); count += 1
                except Exception as e:
                    print(f"[warn] copy failed {p} -> {dst}: {e}")
    return count


def run_renamer(dest_root: Path, profiles: List[str], strict_ocr: bool, prefer_start: bool,
                workers: int, max_ocr: int, extra_args: List[str]) -> int:
    base_cmd = [sys.executable, "-m", "dashcam_tools.rename", "--dir", str(dest_root), "--workers", str(workers),
                "--max-ocr-per-run", str(max_ocr)]
    if strict_ocr:
        base_cmd.append("--strict-ocr")
    if prefer_start:
        base_cmd.append("--prefer-start")
    base_cmd.append("--only-unnamed")
    stamp = dt.datetime.now().strftime("%Y%m%d")
    base_cmd += ["--audit", str(dest_root / f"ingest_audit_{stamp}.csv")]
    base_cmd += extra_args
    failures = 0
    for prof in profiles:
        cmd = base_cmd + ["--profile", prof]
        print("[renamer]", " ".join(cmd))
        completed = subprocess.run(cmd, check=False)
        if completed.returncode != 0:
            failures += 1
            print(f"[error] renamer failed for profile {prof}: exit {completed.returncode}", file=sys.stderr)
    return failures


def cli(argv=None):
    ap = argparse.ArgumentParser(description="Ingest from folders or E01 images, then rename via on-screen timestamps")
    ap.add_argument("--src", action="append", required=True, help="Source path (folder or .E01). Repeat for multiple.")
    ap.add_argument("--dest", default=str(Path.home()/"DashcamImports"), help="Destination root for copied videos")
    ap.add_argument("--profiles", default="blackvue,thinkware,generic", help="Comma list of renamer profiles in order")
    ap.add_argument("--strict-ocr", action="store_true", help="Rename only when OCR time is extracted")
    ap.add_argument("--prefer-start", action="store_true", help="Estimate clip start time from duration where applicable")
    ap.add_argument("--workers", type=int, default=6, help="Parallel workers for fast stages")
    ap.add_argument("--max-ocr-per-run", type=int, default=30, help="OCR attempts budget per run")
    ap.add_argument("--renamer-args", default="", help="Extra args to pass to renamer (quoted string)")
    args = ap.parse_args(argv)

    dest_root = Path(args.dest).expanduser().resolve()
    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    extra_args = args.renamer_args.split() if args.renamer_args else []

    dest_root.mkdir(parents=True, exist_ok=True)

    total_copied = 0
    failures = 0
    for src_s in args.src:
        src = Path(src_s).expanduser().resolve()
        if not src.exists():
            print(f"[skip] not found: {src}"); failures += 1; continue
        stamp = dt.datetime.now().strftime("%Y/%m/%d")
        rollin = dest_root / stamp / src.stem
        rollin.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            print(f"[ingest:dir] {src} -> {rollin}")
            try:
                rsync_copy(src, rollin)
            except RuntimeError as exc:
                print(f"[error] {exc}", file=sys.stderr)
                failures += 1
                continue
        elif src.suffix.lower() == ".e01":
            print(f"[ingest:e01] {src} -> {rollin}"); ensure_tools_or_warn()
            extract_dir = extract_from_e01(src, rollin / "_stage")
            if extract_dir is None:
                print(f"[skip:e01] could not extract from {src}"); failures += 1; continue
            total_copied += collect_videos(extract_dir, rollin)
        else:
            print(f"[skip] unsupported source type: {src}"); failures += 1; continue
        for dirpath, _, files in os.walk(rollin):
            for name in files:
                if Path(name).suffix.lower() in VIDEO_EXTS:
                    total_copied += 1
    print(f"Ingest complete. copied~={total_copied}")
    failures += run_renamer(dest_root, profiles, args.strict_ocr, args.prefer_start, args.workers, args.max_ocr_per_run, extra_args)
    return 1 if failures else 0

if __name__ == "__main__":
    raise SystemExit(cli())
