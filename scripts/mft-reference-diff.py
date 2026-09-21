#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   uv run scripts/mft-reference-diff.py \
#       --mft <MFT.bin> --ils <ils -e output> --fls <fls -rp output> \
#       --output <diff-report.json> --json
#
# Compares RapidTriage's native $MFT record parse against Sleuth Kit
# reference exports on the SAME evidence source:
#   * ils -e  -> per-inode allocation status (a = allocated, f = free)
#   * fls -rp -> recursive path listing ('*' marks deleted entries)
#
# Emits inode coverage, deleted-detection TP/FP/FN/TN, path agreement,
# and size-field agreement. Engineering measurement on real evidence;
# not release evidence without reviewer sign-off.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.filesystem import (
    parse_mft_record_headers,
)

# Window size must stay under the parser's 5000-record cap; 4 MiB holds at
# most 4096 records at 1024 bytes/record.
WINDOW_BYTES = 4 * 1024 * 1024
WINDOW_OVERLAP = 4096
RECORD_ALIGNMENT = 1024


def parse_ils(path: Path) -> dict[int, dict[str, object]]:
    rows: dict[int, dict[str, object]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        header_seen = False
        for line in handle:
            line = line.rstrip("\n")
            if not header_seen:
                if line.startswith("st_ino|"):
                    header_seen = True
                continue
            fields = line.split("|")
            if len(fields) < 11:
                continue
            try:
                inode = int(fields[0])
            except ValueError:
                continue
            rows[inode] = {
                "alloc": fields[1],
                "size": _int(fields[10]),
                "nlink": _int(fields[9]),
                "mtime": _int(fields[4]),
            }
    return rows


def parse_fls(path: Path) -> dict[int, dict[str, object]]:
    # TSK Windows builds write filenames in the console codepage (cp949 on
    # Korean Windows); decoding as UTF-8 turns Hangul names into '?' runs.
    rows: dict[int, dict[str, object]] = {}
    with path.open("r", encoding="cp949", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if ":" not in line:
                continue
            meta, _, name = line.partition(":\t")
            if not name:
                continue
            deleted = "*" in meta
            token = meta.split()[-1].lstrip("*").strip()
            inode_str = token.split("-")[0]
            try:
                inode = int(inode_str)
            except ValueError:
                continue
            entry_type = meta.split()[0] if meta.split() else ""
            rows[inode] = {
                "path": name.strip(),
                "deleted": deleted,
                "entry_type": entry_type,
            }
    return rows


def parse_mft_windows(mft_path: Path) -> tuple[dict[int, dict[str, object]], dict[str, int]]:
    """Run the real parser over the full $MFT in bounded windows.

    ``parse_mft_record_headers`` finds FILE magic anywhere in the blob;
    windows are record-aligned so ``record_number_candidate`` is the true
    inode. Records are deduplicated by absolute record offset across the
    overlap region; a record whose offset is not 1024-aligned is a magic
    inside record content (counted separately, excluded from the map).
    """
    records: dict[int, dict[str, object]] = {}
    stats = {"windows": 0, "raw_records": 0, "unaligned_magic": 0, "duplicate_offsets": 0}
    size = mft_path.stat().st_size
    seen_offsets: set[int] = set()
    with mft_path.open("rb") as handle:
        base = 0
        while base < size:
            handle.seek(base)
            window = handle.read(WINDOW_BYTES + WINDOW_OVERLAP)
            if not window:
                break
            stats["windows"] += 1
            for record in parse_mft_record_headers(window):
                stats["raw_records"] += 1
                abs_offset = base + int(record["record_offset"])
                if abs_offset in seen_offsets:
                    stats["duplicate_offsets"] += 1
                    continue
                seen_offsets.add(abs_offset)
                if abs_offset % RECORD_ALIGNMENT:
                    stats["unaligned_magic"] += 1
                    continue
                # Keep only the fields the diff needs; full parsed records
                # carry attributes/strings that exhaust memory at ~1.4M rows.
                records[abs_offset // RECORD_ALIGNMENT] = _slim(record)
            consumed = min(len(window), WINDOW_BYTES)
            if len(window) < WINDOW_BYTES + WINDOW_OVERLAP:
                break
            base += consumed
    return records, stats


def _slim(record: dict[str, object]) -> dict[str, object]:
    return {
        "in_use": bool(record.get("in_use")),
        "directory": bool(record.get("directory")),
        "validation_status": record.get("validation_status"),
        "file_name_entries": [
            {
                "file_name": e.get("file_name"),
                "namespace": e.get("namespace"),
                "parent_record_number": (
                    e.get("parent_reference", {}).get("record_number")
                    if isinstance(e.get("parent_reference"), dict)
                    else None
                ),
            }
            for e in (record.get("file_name_entries") or [])
            if isinstance(e, dict)
        ],
        "path_candidates": (record.get("path_candidates") or [])[:1],
        "data_sizes": [
            _int(a.get("real_size"))
            for a in (record.get("data_attributes") or [])
            if isinstance(a, dict) and a.get("real_size") is not None
        ],
    }


# fls reports the Win32 (long) name; prefer that namespace like
# mft_preferred_file_name_entry does, falling back to DOS 8.3 names.
_NAMESPACE_RANK = {"WIN32": 0, "WIN32_AND_DOS": 1, "POSIX": 2, "DOS": 3}


def preferred_entry(record: dict[str, object]) -> dict[str, object]:
    entries = [e for e in (record.get("file_name_entries") or []) if e.get("file_name")]
    if not entries:
        return {}
    return sorted(
        entries,
        key=lambda e: (
            _NAMESPACE_RANK.get(str(e.get("namespace") or ""), 9),
            -len(str(e.get("file_name") or "")),
        ),
    )[0]


def preferred_name(record: dict[str, object]) -> str:
    name = str(preferred_entry(record).get("file_name") or "")
    if name:
        return name
    candidates = record.get("path_candidates") or []
    return str(candidates[0]).rsplit("\\", 1)[-1].rsplit("/", 1)[-1] if candidates else ""


def preferred_parent(record: dict[str, object]) -> int | None:
    value = preferred_entry(record).get("parent_record_number")
    if value is None:
        return None
    try:
        return int(value) & 0xFFFFFFFFFFFF
    except (TypeError, ValueError):
        return None


def resolve_paths(records: dict[int, dict[str, object]]) -> dict[int, str]:
    """Iterative parent-chain resolution, mirroring fls -p output."""
    names = {num: preferred_name(rec) for num, rec in records.items()}
    parents = {num: preferred_parent(rec) for num, rec in records.items()}
    paths: dict[int, str] = {}
    for _ in range(16):
        changed = False
        for num, name in names.items():
            if num in paths or not name:
                continue
            parent = parents.get(num)
            if parent is None or parent == num:
                # The NTFS root record's own name is "."; fls does not emit
                # it as a path component.
                paths[num] = "" if name in {".", "$Root"} else name
                changed = True
            elif parent in paths:
                paths[num] = f"{paths[parent]}/{name}" if paths[parent] else name
                changed = True
        if not changed:
            break
    return paths


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def mft_data_size(record: dict[str, object]) -> int | None:
    sizes = record.get("data_sizes") or []
    return int(sizes[0]) if sizes else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mft", required=True, type=Path)
    parser.add_argument("--ils", required=True, type=Path)
    parser.add_argument("--fls", type=Path)
    parser.add_argument("--records-cache", type=Path, help="cache parsed slim records as JSON")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    ils = parse_ils(args.ils)
    fls = parse_fls(args.fls) if args.fls else {}
    if args.records_cache and args.records_cache.is_file():
        records = {
            int(k): v
            for k, v in json.loads(args.records_cache.read_text(encoding="utf-8")).items()
        }
        scan_stats = {"windows": 0, "raw_records": len(records), "unaligned_magic": 0,
                      "duplicate_offsets": 0, "from_cache": str(args.records_cache)}
    else:
        records, scan_stats = parse_mft_windows(args.mft)
        if args.records_cache:
            args.records_cache.parent.mkdir(parents=True, exist_ok=True)
            args.records_cache.write_text(json.dumps(records), encoding="utf-8")

    ils_inodes = set(ils)
    parsed_inodes = set(records)

    # Deleted-detection confusion matrix vs ils alloc flags.
    tp = fp = fn = tn = 0
    disagreements: list[dict[str, object]] = []
    for inode in sorted(ils_inodes & parsed_inodes):
        ref_deleted = ils[inode]["alloc"] == "f"
        our_deleted = not bool(records[inode].get("in_use"))
        if our_deleted and ref_deleted:
            tp += 1
        elif our_deleted and not ref_deleted:
            fp += 1
            if len(disagreements) < 50:
                disagreements.append({"inode": inode, "kind": "false-deleted"})
        elif not our_deleted and ref_deleted:
            fn += 1
            if len(disagreements) < 50:
                disagreements.append({"inode": inode, "kind": "missed-deleted"})
        else:
            tn += 1

    # Path agreement vs fls for inodes present in both.
    our_paths = resolve_paths(records)
    path_both = path_match = 0
    path_mismatch_samples: list[dict[str, object]] = []
    for inode, ref in fls.items():
        ours = our_paths.get(inode)
        if ours is None:
            continue
        path_both += 1
        if ours == ref["path"] or ours.endswith("/" + ref["path"]) or ref["path"].endswith("/" + ours):
            path_match += 1
        elif len(path_mismatch_samples) < 50:
            path_mismatch_samples.append(
                {"inode": inode, "fls_path": ref["path"], "rapid_path": ours}
            )

    # Size agreement vs ils for allocated inodes with data attributes.
    size_both = size_match = 0
    for inode in sorted(ils_inodes & parsed_inodes):
        ref_size = ils[inode]["size"]
        our_size = mft_data_size(records[inode])
        if our_size is None:
            continue
        size_both += 1
        if our_size == ref_size:
            size_match += 1

    common = len(ils_inodes & parsed_inodes)
    extra_inodes = parsed_inodes - ils_inodes
    ils_max = max(ils_inodes) if ils_inodes else 0
    extra_beyond_max = sum(1 for i in extra_inodes if i > ils_max)
    total = tp + fp + fn + tn
    report = {
        "schema_version": "mft-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native MFT parser vs Sleuth Kit ils/fls on the same evidence. "
            "Engineering diff only; reviewer sign-off required before release claims."
        ),
        "inputs": {
            "mft": {"path": str(args.mft), "sha256": _sha256(args.mft)},
            "ils": {"path": str(args.ils), "sha256": _sha256(args.ils)},
            "fls": {"path": str(args.fls), "sha256": _sha256(args.fls)} if args.fls else None,
        },
        "scan": scan_stats,
        "coverage": {
            "ils_inode_count": len(ils_inodes),
            "parsed_inode_count": len(parsed_inodes),
            "common_inode_count": common,
            "parsed_missing_from_ils": len(extra_inodes),
            "parsed_extra_beyond_ils_max": extra_beyond_max,
            "parsed_extra_within_ils_range": len(extra_inodes) - extra_beyond_max,
            "ils_missing_from_parser": len(ils_inodes - parsed_inodes),
            "inode_coverage": round(common / len(ils_inodes), 6) if ils_inodes else None,
        },
        "deleted_detection": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "evaluated": total,
            "precision": round(tp / (tp + fp), 6) if tp + fp else None,
            "recall": round(tp / (tp + fn), 6) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else None,
            "flag_agreement": round((tp + tn) / total, 6) if total else None,
            "samples": disagreements,
        },
        "path_agreement": {
            "compared": path_both,
            "matched": path_match,
            "match_rate": round(path_match / path_both, 6) if path_both else None,
            "mismatch_samples": path_mismatch_samples,
        },
        "size_agreement": {
            "compared": size_both,
            "matched": size_match,
            "match_rate": round(size_match / size_both, 6) if size_both else None,
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        cov = report["coverage"]
        det = report["deleted_detection"]
        print(f"inode coverage: {cov['inode_coverage']} ({common}/{cov['ils_inode_count']})")
        print(
            f"deleted detection: precision={det['precision']} recall={det['recall']} "
            f"fpr={det['false_positive_rate']} agreement={det['flag_agreement']}"
        )
        print(f"path match: {report['path_agreement']['match_rate']}  size match: {report['size_agreement']['match_rate']}")
        print(f"-> {args.output}")
    return 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
