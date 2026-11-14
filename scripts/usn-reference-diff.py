#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.ntfs>=3.16"]
# ///
# --- How to run ---
#   Export mode (T-205; no extra dependencies):
#     python scripts/usn-reference-diff.py --ours <run>/artifacts/<usn per-kind output .json or JSONL> #         --reference <MFTECmd $J CSV | UsnJrnl2Csv | generic CSV> --output <report.json> --json
#   Journal mode (decoder check):
#     uv run scripts/usn-reference-diff.py --journal <UsnJrnl-$J-tail.bin> --output <report.json> --json
#
# Export mode diffs RapidTriage `usn-record` rows against a dedicated USN parser's CSV,
# keyed by USN number: record recall, file name, reason set, MFT entry number and the
# update timestamp (UTC, second precision; the delete/rename subset is reported apart).
# Shared loader/diff/report: rapidtriage/validation/reference_diff.py. Exit 0 clean,
# 1 differences, 2 input error.
#
# Journal mode compares RapidTriage's native USN v2/v3/v4 record decode
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
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.filesystem import parse_usn_record_scan
from rapidtriage.validation import reference_diff as rd

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


def journal_main(argv: list[str] | None = None) -> int:
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


# ---------------------------------------------------------------------------
# Export mode (T-205)
# ---------------------------------------------------------------------------

USN_ARTIFACT_TYPES = ("usn-record",)
ENTRY_MASK = (1 << 48) - 1
DELETE_RENAME_REASONS = frozenset({"filedelete", "renameoldname", "renamenewname"})
REF_USN = ("updatesequencenumber", "usn", "usnnumber")
REF_TIME = ("updatetimestamp", "timestamp", "timestamputc", "datetime", "time")
REF_NAME = ("name", "filename")
REF_REASON = ("updatereasons", "reason", "reasons")
REF_ENTRY = ("entrynumber", "mftreference", "mftentry", "filereferencenumber", "filereference")


def reason_set(value: object) -> frozenset[str]:
    """``FILE_DELETE|CLOSE``, ``FileDelete|Close``, ``USN_REASON_CLOSE`` or a list -> ``{"filedelete", "close"}``."""
    parts = value if isinstance(value, (list, tuple, set, frozenset)) else re.split(r"[|+,;\s]+", str(value or ""))
    names = set()
    for part in parts:
        token = re.sub(r"[^0-9a-z]", "", str(part).casefold().removeprefix("usn_reason_"))
        if token:
            names.add(token)
    return frozenset(names)


def leaf_name(value: object) -> str:
    return rd.normalize_text(str(value or "").replace("\\", "/").rsplit("/", 1)[-1])


def entry_number(value: object) -> int | None:
    number = rd.parse_int(value)
    return None if number is None else number & ENTRY_MASK


def usn_row(usn: int, name: object, timestamp: object, reasons: object, entry: object) -> rd.KeyedRow:
    fields = {"file_name": leaf_name(name), "timestamp": timestamp, "reasons": reason_set(reasons), "entry_number": entry_number(entry)}
    return rd.KeyedRow(keys=[str(usn)], fields=fields, label={"usn": usn, "file_name": fields["file_name"], "timestamp": timestamp})


def build_usn_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, usn=REF_USN, timestamp=REF_TIME)
    if "updatesequencenumber" in header:
        tool = "MFTECmd ($J CSV)"
    elif "mftreference" in header:
        tool = "UsnJrnl2Csv"
    else:
        tool = "generic USN CSV"
    reference: list[rd.KeyedRow] = []
    reference_reasons: dict[str, frozenset[str]] = {}
    for line, row in enumerate(table, start=2):
        usn = rd.parse_int(rd.pick(row, *REF_USN))
        if usn is None:
            rd.add_warning(warnings, f"기준 {line}행에 USN 번호가 없어 건너뛰었습니다")
            continue
        stamp = rd.safe_timestamp(rd.pick(row, *REF_TIME), args.reference_tzinfo, warnings, f"기준 {line}행")
        keyed = usn_row(usn, rd.pick(row, *REF_NAME), stamp, rd.pick(row, *REF_REASON), rd.pick(row, *REF_ENTRY))
        reference.append(keyed)
        reference_reasons[keyed.keys[0]] = keyed.fields["reasons"]  # type: ignore[assignment]
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, USN_ARTIFACT_TYPES, warnings):
        usn = rd.parse_int(rd.rapid_field(row, "usn"))
        if usn is None:
            continue
        stamp = rd.safe_timestamp(rd.rapid_field(row, "timestamp"), args.ours_tzinfo, warnings, f"우리 USN {usn}")
        ours.append(
            usn_row(
                usn,
                rd.rapid_field(row, "file_name", "file_path", "name"),
                stamp,
                rd.rapid_field(row, "reason_flags", "reason"),
                rd.rapid_field(row, "record_number", "file_reference_number"),
            )
        )

    def delete_rename(result: rd.DiffResult) -> dict[str, object]:
        subset = [key for key, reasons in reference_reasons.items() if reasons & DELETE_RENAME_REASONS]
        time_mismatch = [
            item["key"]
            for item in result.mismatched
            if "timestamp" in item["fields"] and reference_reasons.get(str(item["key"]), frozenset()) & DELETE_RENAME_REASONS  # type: ignore[operator]
        ]
        return {
            "delete_rename": {
                "reference_records": len(subset),
                "timestamp_mismatched": len(time_mismatch),
                "timestamp_mismatched_keys": time_mismatch[: max(args.max_list, 0) or None],
            }
        }

    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool=tool,
        key_fields=["usn"],
        compared_fields=["file_name", "timestamp", "reasons", "entry_number"],
        extra_sections=delete_rename,
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(item == "--journal" or item.startswith("--journal=") for item in argv):
        return journal_main(argv)
    return rd.run_comparison_cli(
        argv,
        comparison="usn",
        description="Diff RapidTriage usn-record rows against a USN parser CSV (key = USN number).",
        build=build_usn_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
