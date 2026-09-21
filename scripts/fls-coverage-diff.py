#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   uv run scripts/fls-coverage-diff.py \
#       --files-json <rapidtriage-files.json> --fls <fls -rp output> \
#       --strip-prefix "_disk_image/filesystem" --output <report.json> --json
#
# Compares the file set a RapidTriage run extracted (or inventoried) with
# Sleuth Kit `fls -rp` enumeration of the same image: coverage of the
# fls-allocated namespace, plus extracted entries absent from fls.
# Engineering measurement; not release evidence.
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
import unicodedata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.json_stream import iter_array_items


def norm(path: str) -> str:
    # NFC-fold so NFC/NFD differences between tool output encodings do not
    # masquerade as coverage gaps (NTFS stores UTF-16; console fls output
    # may decompose Hangul).
    return unicodedata.normalize("NFC", path.replace("\\", "/").strip("/"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files-json", required=True, type=Path)
    parser.add_argument("--fls", required=True, type=Path)
    parser.add_argument(
        "--strip-prefix",
        default="",
        help="leading path components to strip from extracted paths before comparing",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    prefix = norm(args.strip_prefix)

    # TSK Windows builds emit filenames in the console codepage; on Korean
    # Windows that is cp949. Decode accordingly so Hangul names compare.
    fls_paths: set[str] = set()
    fls_dirs: set[str] = set()
    fls_deleted = 0
    with args.fls.open("r", encoding="cp949", errors="replace") as handle:
        for line in handle:
            meta, sep, name = line.partition(":\t")
            if not sep or not name.strip():
                continue
            if "*" in meta:
                fls_deleted += 1
                continue  # deleted namespace; extracted trees hold live files
            entry_type = meta.split()[0] if meta.split() else ""
            if entry_type.startswith("d/"):
                fls_dirs.add(norm(name.strip()))
            else:
                fls_paths.add(norm(name.strip()))

    extracted: set[str] = set()
    skipped_prefix = 0
    for row in iter_array_items(args.files_json, "candidates"):
        raw = norm(str(row.get("path") or ""))
        # Absolute Windows path -> drop drive letter, then strip prefix.
        if len(raw) > 2 and raw[1] == ":":
            raw = raw[2:].lstrip("/")
        if prefix:
            if raw.lower().startswith(prefix.lower() + "/"):
                raw = raw[len(prefix) + 1 :]
            elif raw.lower() == prefix.lower():
                raw = ""
            else:
                skipped_prefix += 1
                continue
        if raw:
            extracted.add(raw)

    covered = extracted & fls_paths
    missing_from_fls = extracted - fls_paths
    fls_not_extracted = fls_paths - extracted
    report = {
        "schema_version": "fls-coverage-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Compares a RapidTriage extracted-file set with fls -rp enumeration. "
            "Path normalization is separator/prefix only; case and 8.3 aliases "
            "are not folded."
        ),
        "inputs": {
            "files_json": {"path": str(args.files_json), "sha256": _sha256(args.files_json)},
            "fls": {"path": str(args.fls), "sha256": _sha256(args.fls)},
            "strip_prefix": prefix,
        },
        "fls": {
            "allocated_file_paths": len(fls_paths),
            "allocated_dir_paths": len(fls_dirs),
            "deleted_entries_excluded": fls_deleted,
        },
        "extracted": {
            "unique_paths": len(extracted),
            "skipped_outside_prefix": skipped_prefix,
        },
        "coverage": {
            "extracted_present_in_fls": len(covered),
            "extracted_absent_from_fls": len(missing_from_fls),
            "fls_allocated_not_extracted": len(fls_not_extracted),
            "extraction_coverage_of_fls": (
                round(len(covered) / len(fls_paths), 6) if fls_paths else None
            ),
            "extracted_fls_match_rate": (
                round(len(covered) / len(extracted), 6) if extracted else None
            ),
        },
        "samples": {
            "extracted_absent_from_fls": sorted(missing_from_fls)[:50],
            "fls_allocated_not_extracted": sorted(fls_not_extracted)[:50],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        cov = report["coverage"]
        print(
            f"fls allocated files: {report['fls']['allocated_file_paths']}  extracted: {report['extracted']['unique_paths']}"
        )
        print(
            f"coverage={cov['extraction_coverage_of_fls']} "
            f"match_rate={cov['extracted_fls_match_rate']} -> {args.output}"
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
