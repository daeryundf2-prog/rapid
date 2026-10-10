#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["regipy>=6.0.0"]
# ///
# --- How to run ---
#   uv run scripts/amcache-reference-diff.py --amcache <Amcache.hve> --output <report.json> --json
#
# Compares RapidTriage's Amcache extraction — native schema-row decode
# (nk/vk cells) plus bounded string pivots — against regipy's
# schema-decoded Root\InventoryApplicationFile / Root\File rows.
#
# Measures recall (fraction of real decoded paths surfaced) and
# precision (fraction of candidates that are real), plus SHA1 FileId
# overlap. InventoryApplication/Programs rows are program records, not
# file paths, and are excluded from the path comparison.
#
# Engineering measurement only; regipy is not in the recognized
# trusted-tool list, so results stay engineering_check_only.
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
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.execution import build_native_amcache_records

EXE_ARG_RE = re.compile(r"(\.[a-z0-9]{2,5})\s+[-/].*$", re.IGNORECASE)


def _canon_path(value: object) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    # Strip command-line arguments appended after the binary extension
    # (e.g. "WERFAULT.EXE -u -p 21952" -> "...WERFAULT.EXE").
    match = EXE_ARG_RE.search(text)
    if match:
        text = text[: match.end(1)]
    return text.lower().rstrip("\\")


def rapid_side(path: Path) -> dict[str, object]:
    paths: set[str] = set()
    sha1s: set[str] = set()
    entries = 0
    schema_rows = 0
    for record in build_native_amcache_records(path):
        if record.artifact_type == "amcache-hive":
            for candidate in record.details.get("path_candidates") or []:
                canon = _canon_path(candidate)
                if canon:
                    paths.add(canon)
            for candidate in record.details.get("sha1_candidates") or []:
                sha1s.add(str(candidate).lower())
        elif record.artifact_type == "amcache-entry":
            entries += 1
            canon = _canon_path(record.details.get("executable_path"))
            if canon:
                paths.add(canon)
            for candidate in record.details.get("sha1_candidates") or []:
                sha1s.add(str(candidate).lower())
        elif record.artifact_type == "amcache-schema-row":
            schema_rows += 1
            if record.details.get("section") not in {"InventoryApplicationFile", "File"}:
                continue  # InventoryApplication/Programs rows are programs, not file paths
            canon = _canon_path(record.details.get("executable_path"))
            if canon:
                paths.add(canon)
            sha1 = str(record.details.get("sha1") or "")
            if sha1:
                sha1s.add(sha1)
    return {"paths": paths, "sha1s": sha1s, "entry_records": entries, "schema_rows": schema_rows}


def trusted_side(path: Path) -> dict[str, object]:
    from regipy.registry import RegistryHive

    hive = RegistryHive(str(path))
    root = hive.root.get_subkey("Root")
    paths: set[str] = set()
    sha1s: set[str] = set()
    rows = 0
    for section_name in ("InventoryApplicationFile", "File"):
        try:
            section = root.get_subkey(section_name)
        except Exception:
            continue
        for entry in section.iter_subkeys():
            rows += 1
            values = {v.name: v.value for v in entry.iter_values()}
            long_path = values.get("LowerCaseLongPath") or values.get("FullPath") or ""
            canon = _canon_path(long_path)
            if canon:
                paths.add(canon)
            file_id = str(values.get("FileId") or "")
            if len(file_id) == 44 and file_id.startswith("0000"):
                sha1s.add(file_id[4:].lower())
            elif len(file_id) == 40:
                sha1s.add(file_id.lower())
    return {"paths": paths, "sha1s": sha1s, "schema_rows": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amcache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    digest = hashlib.sha256(args.amcache.read_bytes()).hexdigest()

    errors: list[str] = []
    try:
        rapid = rapid_side(args.amcache)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        rapid = {"paths": set(), "sha1s": set(), "entry_records": 0, "schema_rows": 0}
    try:
        trusted = trusted_side(args.amcache)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = {"paths": set(), "sha1s": set(), "schema_rows": 0}

    rapid_paths: set = rapid["paths"]
    trusted_paths: set = trusted["paths"]
    common_paths = rapid_paths & trusted_paths
    common_sha1 = rapid["sha1s"] & trusted["sha1s"]

    report = {
        "schema_version": "amcache-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native nk/vk schema-row decode plus bounded "
            "string pivots vs regipy schema decode. String pivots may "
            "add candidate rows beyond declared schema subkeys "
            "(precision below 1.0 by design)."
        ),
        "amcache": str(args.amcache),
        "amcache_sha256": digest,
        "trusted_schema_rows": trusted["schema_rows"],
        "trusted_unique_paths": len(trusted_paths),
        "rapid_path_candidates": len(rapid_paths),
        "rapid_entry_records": rapid["entry_records"],
        "rapid_schema_rows": rapid["schema_rows"],
        "path_recall": round(len(common_paths) / len(trusted_paths), 6) if trusted_paths else None,
        "path_precision": round(len(common_paths) / len(rapid_paths), 6) if rapid_paths else None,
        "paths_only_in_rapid_sample": sorted(rapid_paths - trusted_paths)[:25],
        "trusted_sha1_fileids": len(trusted["sha1s"]),
        "rapid_sha1_candidates": len(rapid["sha1s"]),
        "sha1_common": len(common_sha1),
        "sha1_only_in_rapid_sample": sorted(rapid["sha1s"] - trusted["sha1s"])[:25],
        "path_normalization": "lowercase; strip args after extension; quote/space strip",
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"rows={trusted['schema_rows']} trusted_paths={len(trusted_paths)} "
            f"rapid_paths={len(rapid_paths)} recall={report['path_recall']} "
            f"precision={report['path_precision']} sha1_common={len(common_sha1)}/{len(rapid['sha1s'])}"
        )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
