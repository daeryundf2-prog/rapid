#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   uv run scripts/fls-coverage-diff.py \
#       --fls <fls -rpl output> --files-json <rapidtriage files.json or extraction manifest> \
#       [--extract-root <tsk_recover output root>] [--stage-dir <output>/_e01] \
#       --strip-prefix "_e01/fs" --output <report.json> --json
#
# Inode-based coverage of a RapidTriage extraction against Sleuth Kit
# `fls -rpl` (long listing: inode, $DATA size, timestamps). Names in TSK win32
# output are ANSI-code-page bytes (cp949 on Korean Windows) and can be lossy, so
# coverage is computed on fls rows (inode identity) after mapping each extracted
# path to a row; see rapidtriage.core.extraction_failures.match_extracted_to_listing
# for the precision tiers. Reports three numbers:
#   (a) content-bearing allocated coverage ($DATA size > 0, ADS and NTFS
#       metafiles excluded),
#   (b) zero-byte listing rate ($DATA size == 0 from the fls size column - never
#       istat's $FILE_NAME Size),
#   (c) ADS listing rate,
# plus a per-directory deficit table. Engineering measurement; not release evidence.
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
from collections.abc import Iterable, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.extraction_failures import (
    ADS_MAP_NAME,
    LONG_PATH_MAP_NAME,
    ZERO_BYTE_LISTING_NAME,
    ExtractedFile,
    FlsEntry,
    classify_listing_entry,
    iter_extracted_files,
    iter_fls_listing,
    match_extracted_to_listing,
    normalize_relative_key,
)
from rapidtriage.core.json_stream import iter_array_items

SCHEMA_VERSION = "fls-coverage-diff-v2-inode"


def strip_candidate_path(raw: str, prefix: str) -> str | None:
    path = raw.replace("\\", "/")
    path = path.removeprefix("//?/")
    if len(path) > 2 and path[1] == ":":
        path = path[2:]
    path = path.strip("/")
    if prefix:
        lowered = path.lower()
        if lowered.startswith(prefix.lower() + "/"):
            return path[len(prefix) + 1 :]
        index = lowered.find("/" + prefix.lower() + "/")
        if index >= 0:
            return path[index + len(prefix) + 2 :]
        return None
    return path


def candidate_inode(row: Mapping[str, object]) -> int | None:
    recovery = row.get("recovery") if isinstance(row.get("recovery"), Mapping) else {}
    for value in (row.get("mft_ref"), row.get("inode"), recovery.get("mft_ref")):
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def load_extracted(
    files_json: Path | None,
    *,
    prefix: str,
    sizes: Mapping[str, int | None],
) -> tuple[list[ExtractedFile], set[int], list[str], int]:
    """Return (path rows to match, inode-carrying rows' inodes, ADS keys, skipped)."""
    rows: list[ExtractedFile] = []
    inodes: set[int] = set()
    ads_keys: list[str] = []
    skipped = 0
    if files_json is None:
        return rows, inodes, ads_keys, skipped
    for row in iter_array_items(files_json, "candidates"):
        if not isinstance(row, Mapping):
            continue
        relative = strip_candidate_path(str(row.get("path") or ""), prefix)
        if relative is None:
            skipped += 1
            continue
        if not relative:
            continue
        if ":" in relative.rsplit("/", 1)[-1]:
            ads_keys.append(normalize_relative_key(relative))
            continue
        inode = candidate_inode(row)
        if inode is not None:
            inodes.add(inode)
            continue
        size = row.get("size")
        rows.append(ExtractedFile(relative, size if isinstance(size, int) else sizes.get(normalize_relative_key(relative))))
    return rows, inodes, ads_keys, skipped


def load_stage_sidecars(stage_dir: Path | None) -> tuple[set[int], set[tuple[int, int | None]]]:
    """Inodes recovered/listed by the gap stage and ADS (inode, attr id) pairs."""
    inodes: set[int] = set()
    ads: set[tuple[int, int | None]] = set()
    if stage_dir is None:
        return inodes, ads
    for name, key in ((LONG_PATH_MAP_NAME, "files"), (ZERO_BYTE_LISTING_NAME, "files")):
        payload = _load_json(stage_dir / name)
        for row in payload.get(key) or ():
            if isinstance(row, Mapping) and isinstance(row.get("inode"), int):
                if name == LONG_PATH_MAP_NAME and row.get("status") not in {"recovered", "size-mismatch"}:
                    continue
                inodes.add(int(row["inode"]))
    payload = _load_json(stage_dir / ADS_MAP_NAME)
    for row in payload.get("streams") or ():
        if isinstance(row, Mapping) and row.get("status") == "recovered" and isinstance(row.get("inode"), int):
            ads.add((int(row["inode"]), row.get("attr_id") if isinstance(row.get("attr_id"), int) else None))
    return inodes, ads


def _load_json(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def build_report(
    entries: list[FlsEntry],
    extracted: Iterable[ExtractedFile],
    *,
    inode_rows: set[int],
    ads_keys: Iterable[str],
    sidecar_inodes: set[int],
    sidecar_ads: set[tuple[int, int | None]],
    top_dirs: int = 30,
) -> dict[str, object]:
    matches, unmatched = match_extracted_to_listing(extracted, entries)
    method_counts: dict[str, int] = {}
    matched_ids: set[int] = set()
    for entry, method in matches.values():
        method_counts[method] = method_counts.get(method, 0) + 1
        matched_ids.add(id(entry))
    covered_inodes = inode_rows | sidecar_inodes
    ads_key_set = set(ads_keys)

    classes: dict[str, list[FlsEntry]] = {}
    for entry in entries:
        classes.setdefault(classify_listing_entry(entry), []).append(entry)

    def covered(entry: FlsEntry) -> bool:
        return id(entry) in matched_ids or entry.inode in covered_inodes

    content = classes.get("content", [])
    zero = classes.get("zero-byte", [])
    ads = classes.get("ads", [])
    content_covered = [entry for entry in content if covered(entry)]
    zero_listed = [entry for entry in zero if covered(entry)]
    ads_listed = [
        entry
        for entry in ads
        if (entry.inode, entry.attr_id) in sidecar_ads or normalize_relative_key(entry.name_hint) in ads_key_set
    ]
    content_inodes = {entry.inode for entry in content}
    content_inodes_covered = {entry.inode for entry in content_covered}

    per_dir: dict[str, dict[str, int]] = {}
    for entry in content + zero:
        parent = entry.name_hint.rpartition("/")[0] or "/"
        row = per_dir.setdefault(parent, {"content": 0, "content_covered": 0, "zero_byte": 0, "zero_byte_listed": 0})
        is_covered = covered(entry)
        if entry.size:
            row["content"] += 1
            row["content_covered"] += int(is_covered)
        else:
            row["zero_byte"] += 1
            row["zero_byte_listed"] += int(is_covered)
    deficits = sorted(
        (
            {
                "directory": directory,
                **counts,
                "content_deficit": counts["content"] - counts["content_covered"],
                "zero_byte_deficit": counts["zero_byte"] - counts["zero_byte_listed"],
            }
            for directory, counts in per_dir.items()
        ),
        key=lambda row: (-row["content_deficit"], -row["zero_byte_deficit"], row["directory"]),
    )
    deficits = [row for row in deficits if row["content_deficit"] or row["zero_byte_deficit"]]
    uncovered_content = [entry for entry in content if not covered(entry)]
    return {
        "listing": {
            "rows": len(entries),
            "class_counts": {name: len(rows) for name, rows in sorted(classes.items())},
            "lossy_name_rows": sum(1 for entry in entries if entry.name_lossy),
        },
        "matching": {
            "method_counts": method_counts,
            "inode_carrying_rows": len(inode_rows),
            "sidecar_inodes": len(sidecar_inodes),
            "extracted_unmatched": len(unmatched),
            "precision_note": (
                "path-exact: NFC+casefold relative path equals the code-page-decoded fls name (exact). "
                "path-wildcard: fls name lossy ('?'), unique regex match among same-depth rows (high). "
                "parent-size: unique same-$DATA-size row in the fls directory mapped from already matched "
                "siblings (medium; mtime is not used because tsk_recover does not preserve it). "
                "inode: files.json/sidecar row carries mft_ref (exact)."
            ),
            "extracted_unmatched_samples": sorted(item.relative_path for item in unmatched)[:50],
        },
        "coverage": {
            "a_content_bearing_allocated": {
                "denominator_rows": len(content),
                "covered_rows": len(content_covered),
                "rate": rate(len(content_covered), len(content)),
                "denominator_unique_inodes": len(content_inodes),
                "covered_unique_inodes": len(content_inodes_covered),
                "rate_unique_inodes": rate(len(content_inodes_covered), len(content_inodes)),
            },
            "b_zero_byte_listing": {
                "denominator_rows": len(zero),
                "listed_rows": len(zero_listed),
                "rate": rate(len(zero_listed), len(zero)),
            },
            "c_ads_listing": {
                "denominator_rows": len(ads),
                "listed_rows": len(ads_listed),
                "rate": rate(len(ads_listed), len(ads)),
                "zone_identifier_rows": sum(1 for entry in ads if entry.stream_name.casefold() == "zone.identifier"),
            },
        },
        "per_directory_deficit": deficits[:top_dirs],
        "samples": {
            "content_not_covered": [
                {"inode": entry.inode, "size": entry.size, "path": entry.name_hint} for entry in uncovered_content[:50]
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fls", required=True, type=Path, help="fls -rpl listing (raw bytes, any code page)")
    parser.add_argument("--files-json", type=Path, help="rapidtriage files.json or {candidates:[{path}]} manifest")
    parser.add_argument("--extract-root", type=Path, help="extraction root to walk for sizes (read-only)")
    parser.add_argument("--stage-dir", type=Path, help="<output>/_e01 with long-path/zero-byte/ADS sidecars")
    parser.add_argument("--strip-prefix", default="", help="leading path components to strip from candidate paths")
    parser.add_argument("--legacy-encoding", default=None, help="code page of fls names (default: system ANSI)")
    parser.add_argument("--top-dirs", type=int, default=30)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.files_json is None and args.extract_root is None:
        parser.error("one of --files-json or --extract-root is required")

    prefix = args.strip_prefix.replace("\\", "/").strip("/")
    entries = list(iter_fls_listing(args.fls, args.legacy_encoding))
    walked: list[ExtractedFile] = list(iter_extracted_files(args.extract_root)) if args.extract_root else []
    sizes = {normalize_relative_key(item.relative_path): item.size for item in walked}
    extracted, inode_rows, ads_keys, skipped = load_extracted(args.files_json, prefix=prefix, sizes=sizes)
    if args.files_json is None:
        extracted = [item for item in walked if ":" not in item.relative_path.rsplit("/", 1)[-1]]
    sidecar_inodes, sidecar_ads = load_stage_sidecars(args.stage_dir)
    body = build_report(
        entries,
        extracted,
        inode_rows=inode_rows,
        ads_keys=ads_keys,
        sidecar_inodes=sidecar_inodes,
        sidecar_ads=sidecar_ads,
        top_dirs=args.top_dirs,
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Coverage is computed on fls -rpl rows by inode after mapping extracted paths to rows. "
            "Zero-byte classification uses the fls $DATA size column. Deleted entries, NTFS metafiles, "
            "and $OrphanFiles are excluded from the denominators."
        ),
        "inputs": {
            "fls": {"path": str(args.fls), "sha256": _sha256(args.fls)},
            "files_json": {"path": str(args.files_json), "sha256": _sha256(args.files_json)} if args.files_json else None,
            "extract_root": str(args.extract_root) if args.extract_root else None,
            "stage_dir": str(args.stage_dir) if args.stage_dir else None,
            "strip_prefix": prefix,
            "skipped_outside_prefix": skipped,
            "extracted_rows": len(extracted),
        },
        **body,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        cov = report["coverage"]
        print(
            "a) content coverage={a}  b) zero-byte listed={b}  c) ADS listed={c} -> {out}".format(
                a=cov["a_content_bearing_allocated"]["rate"],
                b=cov["b_zero_byte_listing"]["rate"],
                c=cov["c_ads_listing"]["rate"],
                out=args.output,
            )
        )
    return 0


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
