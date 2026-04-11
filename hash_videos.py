#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
from typing import Iterable
import csv

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


def main():
    ap = argparse.ArgumentParser(description="Compute hashes for video files and write CSV")
    ap.add_argument("--dir", required=True, help="Target folder or file; scans recursively if folder")
    ap.add_argument("--algo", default="sha256", choices=["sha256", "sha1", "md5"], help="Hash algorithm")
    ap.add_argument("--out", default="hashes.csv", help="Output CSV path")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of files (0=all)")
    args = ap.parse_args()

    root = Path(args.dir).expanduser().resolve()
    outp = Path(args.out).expanduser()
    outp.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with open(outp, "w", newline="") as fp:
        wr = csv.writer(fp)
        wr.writerow(["path", "algo", "hash", "size"])
        for p in iter_videos(root):
            try:
                if args.limit and count >= args.limit:
                    break
                size = p.stat().st_size
                hv = compute_hash(p, args.algo)
                wr.writerow([str(p), args.algo, hv, size])
                print(f"[hash:{args.algo}] {p} {hv} size={size}")
                count += 1
            except KeyboardInterrupt:
                print("Interrupted")
                return 130
            except Exception as e:
                print(f"[error] {p}: {e}")
    print(f"Done. hashed={count} -> {outp}")

if __name__ == "__main__":
    main()
