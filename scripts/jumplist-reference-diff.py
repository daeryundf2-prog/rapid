#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["olefile>=0.47", "LnkParse3>=1.5"]
# ///
# --- How to run ---
#   uv run scripts/jumplist-reference-diff.py --dir <jumplist-dir> --output <report.json>
#
# Compares RapidTriage's native jumplist decode (OLE compound stream
# enumeration + embedded LNK target extraction) against olefile stream
# enumeration + LnkParse3 LNK decode on real .automaticDestinations-ms
# files.
#
# Metrics: per-file stream-set equality, destination count, and
# per-destination target_path agreement (order-aligned).
#
# Engineering measurement only; olefile/LnkParse3 are engineering
# references, not recognized trusted tools.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import io
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.recent_files import (
    extract_jumplist_destinations,
    parse_ole_compound_streams,
)

LNK_MAGIC = b"L\x00\x00\x00"


def trusted_side(path: Path) -> dict[str, object]:
    import LnkParse3
    import olefile

    ole = olefile.OleFileIO(str(path))
    streams: list[str] = []
    destinations: list[dict[str, object]] = []
    errors: list[str] = []
    for entry in ole.listdir():
        name = entry[0]
        streams.append(name)
        if not name.isdigit():
            continue
        try:
            blob = ole.openstream(entry).read()
            lnk = LnkParse3.lnk_file(io.BytesIO(blob))
            parsed = lnk.get_json()
            link_info = parsed.get("link_info") or {}
            header = parsed.get("header") or {}
            destinations.append(
                {
                    "stream": name,
                    "local_base_path": link_info.get("local_base_path"),
                    "common_path_suffix": link_info.get("common_path_suffix"),
                    "creation_time": header.get("creation_time"),
                    "modified_time": header.get("modified_time"),
                    "accessed_time": header.get("accessed_time"),
                }
            )
        except Exception as exc:
            errors.append(f"{name}:{exc!r}"[:120])
    return {"streams": sorted(streams), "destinations": destinations, "errors": errors}


def rapid_side(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    streams = parse_ole_compound_streams(data) if data.startswith(b"\xd0\xcf\x11\xe0") else []
    stream_names = sorted(str(s.get("name") or "") for s in streams)
    destinations = extract_jumplist_destinations(data, streams)
    return {
        "streams": stream_names,
        "destinations": [
            {
                "target_path": d.get("target_path"),
                "target_created_at": d.get("target_created_at"),
                "target_modified_at": d.get("target_modified_at"),
                "target_accessed_at": d.get("target_accessed_at"),
            }
            for d in destinations
        ],
    }


def norm_path(value: object) -> str:
    text = str(value or "").rstrip("\x00").strip()
    # LnkParse3 renders LNK Unicode paths as cp949 bytes decoded with
    # cp1252 (mojibake); round-trip back when possible for comparison.
    try:
        text.encode("cp1252")
    except UnicodeEncodeError:
        return text.lower()
    try:
        repaired = text.encode("cp1252").decode("cp949")
        if repaired != text:
            return repaired.lower()
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    return text.lower()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    files = sorted(args.dir.rglob("*.automaticDestinations-ms"))
    file_reports = []
    total_streams_match = 0
    total_path_match = 0
    total_destinations = 0
    for path in files:
        trusted = trusted_side(path)
        rapid = rapid_side(path)
        stream_match = trusted["streams"] == rapid["streams"]
        trusted_dests = trusted["destinations"]
        rapid_dests = rapid["destinations"]
        path_matches = 0
        for tdest, rdest in zip(trusted_dests, rapid_dests, strict=False):
            if norm_path(tdest.get("local_base_path")) == norm_path(rdest.get("target_path")):
                path_matches += 1
        file_reports.append(
            {
                "file": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "trusted_streams": trusted["streams"],
                "rapid_streams": rapid["streams"],
                "streams_match": stream_match,
                "trusted_destinations": len(trusted_dests),
                "rapid_destinations": len(rapid_dests),
                "path_matches": path_matches,
                "trusted_errors": trusted["errors"],
            }
        )
        total_streams_match += int(stream_match)
        total_path_match += path_matches
        total_destinations += len(trusted_dests)

    report = {
        "schema_version": "jumplist-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native jumplist decode vs olefile+LnkParse3. "
            "olefile/LnkParse3 are engineering references, not recognized trusted tools."
        ),
        "dir": str(args.dir),
        "file_count": len(files),
        "files": file_reports,
        "files_stream_sets_match": total_streams_match,
        "trusted_destination_count": total_destinations,
        "path_matches": total_path_match,
        "path_agreement": round(total_path_match / total_destinations, 6) if total_destinations else None,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"files={len(files)} stream_sets={total_streams_match} "
        f"dests={total_destinations} path_matches={total_path_match} "
        f"agreement={report['path_agreement']}"
    )
    print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
