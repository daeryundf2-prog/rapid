#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.ntfs>=3.16"]
# ///
# --- How to run ---
#   uv run scripts/usn-reference-diff.py --journal <UsnJrnl-$J-tail.bin> --output <report.json> --json
#
# Compares RapidTriage's native USN v2/v3/v4 record decode
# (filesystem.py parse_usn_record_scan) against dissect.ntfs's
# UsnJrnl reader on the same $J stream region.
#
# Metrics: sequential record count, per-record field agreement
# (length, versions, USN, timestamp, file/parent references, reason,
# filename), and filename decode agreement.
#
# Engineering measurement only; dissect.ntfs is not in the recognized
# trusted-tool list, so results stay engineering_check_only. $J is a
# sparse stream; feed a contiguous non-zero region.
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

from rapidtriage.artifacts.windows.filesystem import parse_usn_record_scan

COMPARE_FIELDS = (
    "record_length",
    "major_version",
    "minor_version",
    "usn",
    "timestamp",
    "timestamp_filetime",
    "file_reference_number",
    "parent_file_reference_number",
    "reason_raw",
    "source_info",
    "security_id",
    "file_attributes",
    "file_name",
)


def rapid_records(blob: bytes, limit: int) -> list[dict[str, object]]:
    scan = parse_usn_record_scan(blob, record_limit=limit, max_scan_bytes=len(blob))
    return scan["records"], scan


def trusted_records(path: Path, limit: int) -> list[dict[str, object]]:
    from dissect.ntfs.usnjrnl import UsnJrnl

    rows: list[dict[str, object]] = []
    with path.open("rb") as handle:
        journal = UsnJrnl(handle)
        for record in journal.records():
            raw = record.record
            file_ref = raw.FileReferenceNumber
            parent_ref = raw.ParentFileReferenceNumber
            # _MFT_SEGMENT_REFERENCE: low u32 | high u16 << 32 | seq u16 << 48
            # — identical packing to RapidTriage's little-endian u64 field.
            rows.append(
                {
                    "offset": int(record.offset),
                    "record_length": int(raw.RecordLength),
                    "major_version": int(raw.MajorVersion),
                    "minor_version": int(raw.MinorVersion),
                    "usn": int(raw.Usn),
                    "timestamp": record.timestamp.isoformat() if record.timestamp else "",
                    "timestamp_filetime": int(raw.TimeStamp),
                    "file_reference_number": int(file_ref.SegmentNumberLowPart)
                    | (int(file_ref.SegmentNumberHighPart) << 32)
                    | (int(file_ref.SequenceNumber) << 48),
                    "parent_file_reference_number": int(parent_ref.SegmentNumberLowPart)
                    | (int(parent_ref.SegmentNumberHighPart) << 32)
                    | (int(parent_ref.SequenceNumber) << 48),
                    "reason_raw": int(raw.Reason),
                    "source_info": int(raw.SourceInfo),
                    "security_id": int(raw.SecurityId),
                    "file_attributes": int(raw.FileAttributes),
                    "file_name": str(record.filename),
                }
            )
            if len(rows) >= limit:
                break
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=500_000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    blob = args.journal.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()

    errors: list[str] = []
    try:
        rapid, scan_meta = rapid_records(blob, args.limit)
    except Exception as exc:
        errors.append(f"rapid: {exc!r}"[:200])
        rapid, scan_meta = [], {}
    try:
        trusted = trusted_records(args.journal, args.limit)
    except Exception as exc:
        errors.append(f"trusted: {exc!r}"[:200])
        trusted = []

    field_diffs: dict[str, int] = {field: 0 for field in COMPARE_FIELDS}
    field_diff_samples: dict[str, list[dict[str, object]]] = {field: [] for field in COMPARE_FIELDS}
    sub_ms_timestamp_deltas: list[dict[str, object]] = []
    matched = 0
    compared = min(len(rapid), len(trusted))
    for index in range(compared):
        ours = rapid[index]
        theirs = trusted[index]
        row_ok = True
        for field in COMPARE_FIELDS:
            ours_value = ours.get(field)
            theirs_value = theirs.get(field)
            if field == "timestamp":
                ours_raw = str(ours_value or "").replace("+00:00", "")
                theirs_raw = str(theirs_value or "").replace(" ", "T").replace("+00:00", "")
                if ours_raw != theirs_raw:
                    sub_ms_timestamp_deltas.append(
                        {"index": index, "rapid": ours_raw, "trusted": theirs_raw}
                    )
                # ISO rendering is advisory; the authoritative check is the
                # raw FILETIME integer (timestamp_filetime), compared above.
                continue
            if ours_value != theirs_value:
                field_diffs[field] += 1
                row_ok = False
                if len(field_diff_samples[field]) < 5:
                    field_diff_samples[field].append(
                        {"index": index, "rapid": str(ours.get(field))[:120], "trusted": str(theirs.get(field))[:120]}
                    )
        if row_ok:
            matched += 1

    report = {
        "schema_version": "usn-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native USN record decode vs dissect.ntfs UsnJrnl. "
            "dissect.ntfs is an engineering reference, not a recognized trusted tool. "
            "The $J input is a contiguous non-zero region of the sparse journal stream."
        ),
        "journal_input": str(args.journal),
        "journal_sha256": digest,
        "input_bytes": len(blob),
        "rapid_records": len(rapid),
        "trusted_records": len(trusted),
        "compared_records": compared,
        "fully_matched_records": matched,
        "record_agreement": round(matched / compared, 6) if compared else None,
        "field_diff_counts": field_diffs,
        "field_diff_samples": {key: value for key, value in field_diff_samples.items() if value},
        "sub_ms_timestamp_deltas_count": len(sub_ms_timestamp_deltas),
        "sub_ms_timestamp_deltas_sample": sub_ms_timestamp_deltas[:10],
        "rapid_scan_metadata": {
            key: scan_meta.get(key)
            for key in ("skipped_bytes_during_scan", "partial_record_at_scan_end", "timestamp_range", "large_record_count")
        },
        "errors": errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"rapid={len(rapid)} trusted={len(trusted)} compared={compared} "
            f"matched={matched} agreement={report['record_agreement']}"
        )
        nonzero = {key: value for key, value in field_diffs.items() if value}
        print("field diffs:", nonzero or "none")
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
