#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
"""
Dashcam video renamer: extracts start time from videos then renames.
Sources (fast→slow):
  1) Container metadata (ffprobe creation_time)
  2) Filename patterns (VID_20240701_120304, 2024-07-01_12-03-04, 한글 날짜 등)
  3) OCR on sampled frames (optional; ROI profiles)
  4) File times (birth/mtime; optional start-time correction by duration)

Scale features:
  - Incremental cache: SQLite state to skip unchanged files automatically
  - Parallel stage: fast pass (metadata/filename/filetime) with --workers
  - OCR budget: --no-ocr or --max-ocr-per-run to cap heavy work per run

Clock mis-set handling:
  - Manual offset: --offset "+9h" | "-5m30s" | "+01:00:00"
  - Auto-calibration: --auto-offset mtime|birth (median diff) with --auto-offset-apply
  - Anchor: --anchor-file FILE --anchor-time "YYYY-MM-DD HH:MM:SS"
"""

import argparse
import dataclasses
import datetime as dt
import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from typing import Iterable, List, Optional, Sequence, Tuple, Set, Dict, Any

# Optional deps (loaded lazily when OCR/video needed)
_cv2 = None
_np = None
_pytesseract = None

VIDEO_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".mts", ".m2ts", ".ts"}

DATE_PATTERNS = [
    re.compile(r"(?P<y>20\d{2})[./-](?P<m>\d{1,2})[./-](?P<d>\d{1,2})[ T_\-]*(?P<H>\d{1,2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?\s*(?P<ampm>(?:AM|PM|am|pm)?)"),
    re.compile(r"(?P<d>\d{1,2})[./-](?P<m>\d{1,2})[./-](?P<y>20\d{2})[ T_\-]*(?P<H>\d{1,2}):(?P<M>\d{2})(?::(?P<S>\d{2}))?\s*(?P<ampm>(?:AM|PM|am|pm)?)"),
    re.compile(r"(?P<y>20\d{2})[./-](?P<m>\d{1,2})[./-](?P<d>\d{1,2})[ _T-]+(?P<H>\d{1,2})[-:](?P<M>\d{2})[-:](?P<S>\d{2})\s*(?P<ampm>(?:AM|PM|am|pm)?)"),
    re.compile(r"(?P<y>20\d{2})(?P<m>\d{2})(?P<d>\d{2})[ _-]?(?P<H>\d{2})(?P<M>\d{2})(?P<S>\d{2})"),
    re.compile(r"(?P<y>\d{2})(?P<m>\d{2})(?P<d>\d{2})[ _-]?(?P<H>\d{2})(?P<M>\d{2})(?P<S>\d{2})"),
    re.compile(r"(?P<y>20\d{2})\s*년\s*(?P<m>\d{1,2})\s*월\s*(?P<d>\d{1,2})\s*일\s*(?P<H>\d{1,2})\s*(?:시|:)\s*(?P<M>\d{2})\s*(?::|분)\s*(?P<S>\d{2})?"),
]

@dataclasses.dataclass
class OCRSettings:
    rois: List[Tuple[float, float, float, float]]
    frames_to_try: int = 6
    seconds_spread: float = 30.0
    preprocess_variants: int = 6
    min_year: int = 2010

VENDOR_PROFILES = {
    "thinkware": OCRSettings(rois=[(0.62, 0.84, 0.36, 0.14), (0.00, 0.82, 1.0, 0.18)]),
    "blackvue": OCRSettings(rois=[(0.58, 0.84, 0.40, 0.16), (0.0, 0.82, 1.0, 0.18)]),
    "finevu": OCRSettings(rois=[(0.00, 0.82, 1.0, 0.18)]),
    "vicone": OCRSettings(rois=[(0.00, 0.80, 1.0, 0.20), (0.70, 0.00, 0.30, 0.20)]),
    "generic": OCRSettings(rois=[(0.0, 0.0, 1.0, 1.0), (0.0, 0.82, 1.0, 0.18), (0.0, 0.0, 1.0, 0.18)]),
}

# ---------- Lazy deps ----------

def load_optional_deps():
    global _cv2, _np, _pytesseract
    if _cv2 is None:
        import cv2 as _cv2_mod  # type: ignore
        _cv2 = _cv2_mod
    if _np is None:
        import numpy as _np_mod  # type: ignore
        _np = _np_mod
    if _pytesseract is None:
        import pytesseract as _pyt_mod  # type: ignore
        _pytesseract = _pyt_mod

# ---------- Utilities ----------

def ffprobe_creation_time(path: Path) -> Optional[dt.datetime]:
    try:
        out = subprocess.check_output([
            "ffprobe","-v","quiet","-print_format","json","-show_format","-show_streams",str(path)
        ], stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    try:
        info = json.loads(out.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    candidates: List[str] = []
    fmt = info.get("format", {})
    tags = (fmt.get("tags") or {})
    for k in ("creation_time","com.apple.quicktime.creationdate","date"):
        if k in tags:
            candidates.append(tags[k])
    for st in info.get("streams", []) or []:
        st_tags = st.get("tags") or {}
        for k in ("creation_time","com.apple.quicktime.creationdate","date"):
            if k in st_tags:
                candidates.append(st_tags[k])
    for raw in candidates:
        try:
            iso = raw.replace("Z","+00:00").replace(" ","T")
            if re.match(r".*[+-]\d{4}$", iso):
                iso = iso[:-5] + iso[-5:-2] + ":" + iso[-2:]
            return dt.datetime.fromisoformat(iso)
        except Exception:
            continue
    return None


def parse_dt_from_text(text: str, min_year: int = 2010) -> Optional[dt.datetime]:
    text = text.strip()
    for rx in DATE_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        gd = m.groupdict()
        try:
            y = int(gd.get("y") or 0)
            if y < 100:
                y += 2000
            mo = int(gd.get("m") or 1)
            d = int(gd.get("d") or 1)
            H = int(gd.get("H") or 0)
            M = int(gd.get("M") or 0)
            S = int((gd.get("S") or 0) or 0)
            ampm = (gd.get("ampm") or "").lower()
            if ampm == "pm" and 1 <= H <= 11:
                H += 12
            if ampm == "am" and H == 12:
                H = 0
            if y < min_year or not (1 <= mo <= 12) or not (1 <= d <= 31):
                continue
            return dt.datetime(y, mo, d, H, M, S)
        except Exception:
            continue
    m2 = re.search(r"(20\d{2})(\d{2})(\d{2})[^0-9]?([01]?\d|2[0-3])([0-5]\d)([0-5]\d)", text)
    if m2:
        try:
            y, mo, d, H, M, S = map(int, m2.groups())
            if y >= min_year:
                return dt.datetime(y, mo, d, H, M, S)
        except Exception:
            pass
    return None


def parse_dt_from_filename(name: str) -> Optional[dt.datetime]:
    return parse_dt_from_text(name.replace("__","_"))

# ---------- Video/OCR helpers ----------

def open_video(path: Path):
    load_optional_deps()
    cap = _cv2.VideoCapture(str(path))
    if not cap.isOpened():
        raise RuntimeError(f"Cannot open video: {path}")
    return cap


def get_duration_cv(cap) -> float:
    load_optional_deps()
    fps = cap.get(_cv2.CAP_PROP_FPS) or 30.0
    frames = cap.get(_cv2.CAP_PROP_FRAME_COUNT) or 0
    if fps <= 0:
        return 0.0
    return float(frames / fps)


def get_duration_ffprobe(path: Path) -> float:
    try:
        out = subprocess.check_output([
            "ffprobe","-v","error","-show_entries","format=duration","-of","default=noprint_wrappers=1:nokey=1",str(path)
        ])
        return float(out.decode().strip())
    except Exception:
        try:
            cap = open_video(path)
            try:
                return get_duration_cv(cap)
            finally:
                cap.release()
        except Exception:
            return 0.0


def read_frame_at(cap, t_sec: float):
    load_optional_deps()
    fps = cap.get(_cv2.CAP_PROP_FPS) or 30.0
    if fps <= 0:
        fps = 30.0
    cap.set(_cv2.CAP_PROP_POS_MSEC, max(0.0, t_sec) * 1000.0)
    ok, frame = cap.read()
    if not ok or frame is None:
        return None
    return frame


def sample_times(duration_s: float, n: int, spread: float) -> List[float]:
    if duration_s <= 0:
        return [0.0]
    end = min(duration_s, max(3.0, spread))
    slots = [0.2 * i for i in range(n)]
    return [min(end, s / max(0.2 * (n - 1), 1e-6) * end) for s in slots]


def gen_preprocess_variants(img, count: int = 6) -> List:
    load_optional_deps()
    out = []
    gray = _cv2.cvtColor(img, _cv2.COLOR_BGR2GRAY)
    out.append(gray)
    out.append(_cv2.adaptiveThreshold(gray, 255, _cv2.ADAPTIVE_THRESH_GAUSSIAN_C, _cv2.THRESH_BINARY, 31, 15))
    _, th = _cv2.threshold(gray, 0, 255, _cv2.THRESH_BINARY + _cv2.THRESH_OTSU)
    out.append(th)
    out.append(_cv2.bitwise_not(th))
    kernel = _cv2.getStructuringElement(_cv2.MORPH_RECT, (3, 3))
    out.append(_cv2.morphologyEx(gray, _cv2.MORPH_TOPHAT, kernel, iterations=1))
    clahe = _cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    out.append(clahe.apply(gray))
    return out[:max(1, count)]


def crop_roi(img, roi: Tuple[float, float, float, float]):
    h, w = img.shape[:2]
    x, y, rw, rh = roi
    x0 = max(0, int(x * w))
    y0 = max(0, int(y * h))
    x1 = min(w, int((x + rw) * w))
    y1 = min(h, int((y + rh) * h))
    return img[y0:y1, x0:x1]


def ocr_text(img) -> str:
    load_optional_deps()
    cfg = (
        "--oem 1 --psm 6 "
        "-c tessedit_char_whitelist=0123456789:/.-_APMapm년월일시분초"
    )
    try:
        s = _pytesseract.image_to_string(img, config=cfg, lang="eng+kor")
    except Exception:
        s = _pytesseract.image_to_string(img, config=cfg, lang="eng")
    return s


def detect_overlay_start_time(path: Path, profile: OCRSettings) -> Optional[dt.datetime]:
    cap = open_video(path)
    try:
        duration = get_duration_cv(cap)
        samples = sample_times(duration, profile.frames_to_try, profile.seconds_spread)
        for t in samples:
            frame = read_frame_at(cap, t)
            if frame is None:
                continue
            for roi in profile.rois:
                crop = crop_roi(frame, roi)
                for proc in gen_preprocess_variants(crop, profile.preprocess_variants):
                    text = ocr_text(proc)
                    if not text:
                        continue
                    dt_found = parse_dt_from_text(text, min_year=profile.min_year)
                    if dt_found:
                        return dt_found - dt.timedelta(seconds=t)
        return None
    finally:
        cap.release()

# ---------- File time & offsets ----------

def get_file_times(path: Path) -> Tuple[Optional[dt.datetime], Optional[dt.datetime]]:
    try:
        st = os.stat(path)
        birth = getattr(st, "st_birthtime", None)
        birth_dt = dt.datetime.fromtimestamp(birth) if birth else None
        mtime_dt = dt.datetime.fromtimestamp(st.st_mtime)
        return birth_dt, mtime_dt
    except Exception:
        return None, None


def parse_offset_spec(spec: str) -> dt.timedelta:
    spec = (spec or "").strip()
    if not spec:
        return dt.timedelta(0)
    sign = 1
    if spec[0] in "+-":
        if spec[0] == "-":
            sign = -1
        spec = spec[1:]
    spec = spec.strip()
    m = re.match(r"^(\d{1,3}):(\d{2})(?::(\d{2}))?$", spec)
    if m:
        h = int(m.group(1)); mi = int(m.group(2)); s = int(m.group(3) or 0)
        return sign * dt.timedelta(hours=h, minutes=mi, seconds=s)
    total = 0
    for tok in re.finditer(r"(\d+)([hms])", spec):
        val = int(tok.group(1)); unit = tok.group(2)
        if unit == "h": total += val * 3600
        elif unit == "m": total += val * 60
        elif unit == "s": total += val
    if total:
        return sign * dt.timedelta(seconds=total)
    if spec.isdigit():
        return sign * dt.timedelta(seconds=int(spec))
    raise ValueError(f"Invalid offset spec: {spec}")

# ---------- Guess strategies ----------

def best_guess_time(path: Path, profile: OCRSettings, use_metadata_first: bool = True,
                     prefer_start_from_filetime: bool = False, allow_ocr: bool = True) -> Tuple[Optional[dt.datetime], str]:
    # 1) Metadata
    if use_metadata_first:
        meta = ffprobe_creation_time(path)
        if meta:
            return meta, "metadata"
    # 2) Filename
    fn_dt = parse_dt_from_filename(path.stem)
    if fn_dt:
        return fn_dt, "filename"
    # 3) OCR
    if allow_ocr:
        try:
            ocr_dt = detect_overlay_start_time(path, profile)
            if ocr_dt:
                return ocr_dt, "ocr"
        except Exception:
            pass
    # 4) File times
    birth_dt, mtime_dt = get_file_times(path)
    dur = get_duration_ffprobe(path)
    if prefer_start_from_filetime:
        if birth_dt:
            return birth_dt - dt.timedelta(seconds=dur or 0), "birth_minus_duration"
        if mtime_dt:
            return mtime_dt - dt.timedelta(seconds=dur or 0), "mtime_minus_duration"
    else:
        if birth_dt:
            return birth_dt, "birthtime"
        if mtime_dt:
            return mtime_dt, "mtime"
    return None, "none"

# ---------- Naming ----------

def build_new_name(base_dt: dt.datetime, orig: Path, pattern: str = "{Y}{m}{d}_{H}{M}{S}") -> Path:
    repl = {
        "Y": f"{base_dt.year:04d}",
        "m": f"{base_dt.month:02d}",
        "d": f"{base_dt.day:02d}",
        "H": f"{base_dt.hour:02d}",
        "M": f"{base_dt.minute:02d}",
        "S": f"{base_dt.second:02d}",
    }
    stem = pattern
    for k, v in repl.items():
        stem = stem.replace("{" + k + "}", v)
    return orig.with_name(stem + orig.suffix.lower())


def unique_path(p: Path) -> Path:
    if not p.exists():
        return p
    parent = p.parent
    stem = p.stem
    suffix = p.suffix
    i = 1
    while True:
        cand = parent / f"{stem}-{i}{suffix}"
        if not cand.exists():
            return cand
        i += 1

# ---------- Iteration & cache ----------

def iter_videos(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in VIDEO_EXTS:
                yield p


def name_has_datetime(p: Path) -> bool:
    return parse_dt_from_filename(p.stem) is not None


def open_state(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed (
            path TEXT PRIMARY KEY,
            size INTEGER,
            mtime REAL,
            result_name TEXT,
            method TEXT,
            decided_at TEXT
        )
        """
    )
    return conn


def is_unchanged(conn: sqlite3.Connection, p: Path) -> bool:
    try:
        st = p.stat()
    except FileNotFoundError:
        return False
    row = conn.execute("SELECT size, mtime FROM processed WHERE path=?", (str(p),)).fetchone()
    if not row:
        return False
    size, mtime = row
    return int(size) == int(st.st_size) and float(mtime) == float(st.st_mtime)


def upsert_record(conn: sqlite3.Connection, old_path: Path, new_path: Path, method: str):
    st = new_path.stat()
    conn.execute(
        "REPLACE INTO processed(path,size,mtime,result_name,method,decided_at) VALUES (?,?,?,?,?,?)",
        (str(new_path), int(st.st_size), float(st.st_mtime), new_path.name, method, dt.datetime.now().isoformat()),
    )
    if old_path != new_path:
        # Optionally cleanup old key if any
        conn.execute("DELETE FROM processed WHERE path=? AND path<>?", (str(old_path), str(new_path)))

# ---------- Main ----------

def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="Rename dashcam videos using overlay timestamp or metadata")
    ap.add_argument("--dir", default=".", help="Directory to scan recursively")
    ap.add_argument("--profile", default="generic", choices=sorted(VENDOR_PROFILES.keys()), help="Vendor OCR ROI profile")
    ap.add_argument("--roi", action="append", default=[], help="Extra ROI x,y,w,h in 0..1 fractions; can be repeated")
    ap.add_argument("--dry-run", action="store_true", help="Only print planned actions")
    ap.add_argument("--pattern", default="{Y}{m}{d}_{H}{M}{S}", help="Output filename pattern")
    ap.add_argument("--no-meta", action="store_true", help="Skip metadata and use filename/OCR/filetime")
    ap.add_argument("--no-ocr", action="store_true", help="Disable OCR stage entirely")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of files processed (0=all)")
    ap.add_argument("--only-unnamed", action="store_true", help="Rename only when current filename has no date-time pattern")
    ap.add_argument("--prefer-start", action="store_true", help="When using file times, subtract duration to estimate clip start time")
    ap.add_argument("--audit", default="", help="Optional CSV to append audit rows (src,new,method)")
    ap.add_argument("--offset", default="", help="Manual time offset like +9h, -5m30s, +01:00:00")
    ap.add_argument("--auto-offset", choices=["mtime", "birth"], default=None, help="Estimate constant offset by aligning to file times")
    ap.add_argument("--auto-offset-apply", default="ocr,filename", help="Comma list of methods to apply auto/anchor offset to")
    ap.add_argument("--auto-offset-sample", type=int, default=15, help="Number of files to sample for auto offset")
    ap.add_argument("--auto-offset-max-spread", type=int, default=300, help="Max spread (sec) among sample offsets to accept calibration")
    ap.add_argument("--anchor-file", default="", help="File path whose true start time is known")
    ap.add_argument("--anchor-time", default="", help="True start time for --anchor-file, e.g., 2026-03-14 12:34:56")
    ap.add_argument("--strict-ocr", action="store_true", help="Rename only when OCR time is extracted; ignore other sources")
    ap.add_argument("--workers", type=int, default=4, help="Parallel workers for fast stage (no OCR)")
    ap.add_argument("--max-ocr-per-run", type=int, default=50, help="Maximum number of files to attempt OCR in this run")
    ap.add_argument("--state", default="", help="SQLite path for cache (default: <dir>/.dashcam_rename_state.sqlite)")

    args = ap.parse_args(argv)

    profile = dataclasses.replace(VENDOR_PROFILES[args.profile])
    for roi_str in args.roi:
        try:
            x, y, w, h = map(float, roi_str.split(","))
            profile.rois.append((x, y, w, h))
        except Exception:
            print(f"Invalid --roi: {roi_str} (expected x,y,w,h)", file=sys.stderr)

    root = Path(args.dir).expanduser().resolve()
    if not root.exists():
        print(f"Directory not found: {root}", file=sys.stderr)
        return 2

    state_path = Path(args.state) if args.state else (root / ".dashcam_rename_state.sqlite")
    conn = open_state(state_path)

    audit_fp = None
    audit_writer = None
    if args.audit:
        audit_path = Path(args.audit).expanduser()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_fp = open(audit_path, "a", newline="")
        audit_writer = csv.writer(audit_fp)

    manual_offset = dt.timedelta(0)
    if args.offset:
        try:
            manual_offset = parse_offset_spec(args.offset)
        except Exception as e:
            print(f"Invalid --offset: {e}", file=sys.stderr)
            return 2

    apply_methods: Set[str] = {m.strip() for m in (args.auto_offset_apply or "").split(",") if m.strip()}
    if not apply_methods:
        apply_methods = {"ocr", "filename"}

    # Gather videos (filtered by limit and cache)
    all_videos = [p for p in iter_videos(root)]
    to_process: List[Path] = []
    for p in all_videos:
        # argparse converts '--only-unnamed' to 'only_unnamed'
        if getattr(args, 'only_unnamed', False) and name_has_datetime(p):
            continue
        if is_unchanged(conn, p):
            continue
        to_process.append(p)
        if args.limit and len(to_process) >= args.limit:
            break

    # Stage A: fast pass in parallel (no OCR)
    fast_results: Dict[Path, Tuple[Optional[dt.datetime], str]] = {}
    def fast_task(p: Path):
        dtv, mth = best_guess_time(p, profile, use_metadata_first=not args.no_meta, prefer_start_from_filetime=args.prefer_start, allow_ocr=False)
        return p, (dtv, mth)

    if to_process and args.workers > 1:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = [ex.submit(fast_task, p) for p in to_process]
            for fu in as_completed(futs):
                p, res = fu.result()
                fast_results[p] = res
    else:
        for p in to_process:
            fast_results[p] = fast_task(p)[1]

    # Stage B: OCR on unresolved subset within budget
    if args.strict_ocr and not args.no_ocr:
        # In strict OCR mode, attempt OCR for all candidates regardless of fast-pass results
        unresolved = list(to_process)
    else:
        unresolved = [p for p, (dtv, mth) in fast_results.items() if dtv is None and not args.no_ocr]
    ocr_budget = max(0, args.max_ocr_per_run)
    ocr_attempted = 0

    for p in unresolved:
        if ocr_attempted >= ocr_budget:
            break
        dtv, mth = best_guess_time(p, profile, use_metadata_first=not args.no_meta, prefer_start_from_filetime=args.prefer_start, allow_ocr=True)
        fast_results[p] = (dtv, mth)
        ocr_attempted += 1

    # Auto/anchor offsets
    calibrate_offset = dt.timedelta(0)
    if args.auto_offset:
        sample_paths = list(fast_results.keys())[:max(3, args.auto_offset_sample)]
        diffs: List[float] = []
        for sp in sample_paths:
            dtv, mth = fast_results.get(sp, (None, ""))
            if dtv is None or mth not in apply_methods:
                continue
            b, m = get_file_times(sp)
            ref = b if args.auto_offset == "birth" else m
            if ref is None:
                continue
            dur = get_duration_ffprobe(sp)
            if args.prefer_start:
                ref = ref - dt.timedelta(seconds=dur or 0)
            diffs.append((ref - dtv).total_seconds())
        if len(diffs) >= 3:
            med = median(diffs)
            if (max(diffs) - min(diffs)) <= max(1, args.auto_offset_max_spread):
                calibrate_offset = dt.timedelta(seconds=int(round(med)))
                sign = "+" if med >= 0 else "-"
                print(f"[auto-offset] {args.auto_offset} median {sign}{abs(int(med))}s applied to {sorted(apply_methods)}")
            else:
                print("[auto-offset] skipped (spread too wide)")
        else:
            print("[auto-offset] skipped (insufficient samples)")

    anchor_offset = dt.timedelta(0)
    if args.anchor_file and args.anchor_time:
        anchor_path = Path(args.anchor_file).expanduser()
        if not anchor_path.exists():
            print(f"Anchor file not found: {anchor_path}", file=sys.stderr)
            return 2
        guess, mth = best_guess_time(anchor_path, profile, use_metadata_first=not args.no_meta, prefer_start_from_filetime=args.prefer_start, allow_ocr=not args.no_ocr)
        if guess is None:
            print("Could not determine time for --anchor-file", file=sys.stderr)
            return 2
        true_dt = parse_dt_from_text(args.anchor_time)
        if true_dt is None:
            print("Invalid --anchor-time format", file=sys.stderr)
            return 2
        anchor_offset = true_dt - guess
        print(f"[anchor-offset] {anchor_offset} applied to {sorted(apply_methods)} (anchor method={mth})")

    # Apply actions
    count = 0
    ok = 0
    fail = 0

    try:
        for p in to_process:
            count += 1
            dtv, method = fast_results.get(p, (None, "none"))
            if dtv is None or (args.strict_ocr and method != "ocr"):
                print(f"[skip] {p.name} -> could not detect time (no budget/unsupported)")
                if audit_writer:
                    audit_writer.writerow([str(p), "", "none"])
                continue
            out_dt = dtv + manual_offset
            if method in apply_methods:
                out_dt = out_dt + calibrate_offset + anchor_offset
            newp = build_new_name(out_dt, p, args.pattern)
            newp = unique_path(newp)
            if args.dry-run:
                print(f"[plan:{method}] {p.name} -> {newp.name}")
                ok += 1
                continue
            try:
                if p != newp:
                    p.rename(newp)
                    print(f"[renamed:{method}] {p.name} -> {newp.name}")
                else:
                    print(f"[keep:{method}] {p}")
                upsert_record(conn, p, newp, method)
                conn.commit()
                if audit_writer:
                    audit_writer.writerow([str(p), str(newp), method])
                ok += 1
            except Exception as e:
                fail += 1
                print(f"[error] {p}: {e}", file=sys.stderr)
        print(f"Done. total={len(to_process)} ok={ok} fail={fail} (skipped-cache={len(all_videos)-len(to_process)}); OCR used {ocr_attempted}/{ocr_budget}")
        return 0
    finally:
        if audit_fp:
            audit_fp.close()
        conn.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
