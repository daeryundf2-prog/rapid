#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/mft-coverage-truth.py \
#       --mft <run>/_e01/fs/$MFT [--e01-json <run>/rapidtriage-e01.json] \
#       --output <truth.json> [--json] [--header-only]
#
# Truth table of one NTFS volume from a copy of its $MFT (R8 T-195, GAP-026/358):
#   * header axis   -- base records in use / deleted, files / directories, extension
#                      records, invalid slots (``run_scope.tally_mft_headers``: the same
#                      count the console's processing-scope panel shows);
#   * record detail -- per class, unnamed $DATA resident / non-resident / absent / only in
#                      an extension record, named $DATA streams (ADS), hard links
#                      (> 1 non-DOS $FILE_NAME) and non-DOS $FILE_NAME names (fixup applied, then
#                      ``filesystem.parse_mft_attributes``);
#   * extraction    -- with the run's native extraction stats (``files``,
#                      ``deleted_files``, ``truncated`` ...), a table of what the volume
#                      holds against what the run wrote (allocated copies include one copy
#                      per hard-link name).
# Feeds T-038 / T-204: compare these numbers with Sleuth Kit ``ils -e`` / ``fls -rp``
# (scripts/mft-reference-diff.py, scripts/fls-coverage-diff.py). Until that comparison the
# numbers are ``basis: inferred``. Engineering measurement only: run it on real evidence
# outside Git and keep the report there; it is not release evidence.
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
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.api.app.run_scope import (
    _extraction_stats,
    _mft_record_size,
    tally_mft_headers,
)
from rapidtriage.artifacts.windows.filesystem import (
    apply_mft_update_sequence_fixup,
    int_from,
    parse_mft_attributes,
)

SCHEMA_VERSION = "mft-coverage-truth-v1"
CLASSES = ("in_use_files", "in_use_dirs", "deleted_files", "deleted_dirs")
DATA_ATTRIBUTE = 0x80
READ_RECORDS = 4096
ZONE_IDENTIFIER = "zone.identifier"
DETAIL_KEYS = (
    "records",
    "data_resident",
    "data_nonresident",
    "data_absent",
    "data_in_extension_record",
    "ads_streams",
    "records_with_ads",
    "zone_identifier_streams",
    "attribute_list_records",
    "hard_link_records",
    "link_count_total",
    "non_dos_names",
    "fixup_not_applied",
)


def iter_base_records(path: Path, *, max_records: int | None = None) -> Iterator[tuple[int, bytes]]:
    """``(record number, record bytes)`` of every ``FILE`` base record (extension records skipped)."""
    with path.open("rb") as handle:
        record_size = _mft_record_size(handle.read(0x20))
        handle.seek(0)
        number = 0
        while max_records is None or number < max_records:
            block = handle.read(record_size * READ_RECORDS)
            if len(block) < record_size:
                return
            for start in range(0, len(block) - record_size + 1, record_size):
                if max_records is not None and number >= max_records:
                    return
                record = block[start : start + record_size]
                if record[:4] == b"FILE" and not int_from(record, 0x20, 6):
                    yield number, record
                number += 1


def record_class(record: bytes) -> str:
    flags = int_from(record, 0x16, 2)
    state = "in_use" if flags & 0x01 else "deleted"
    return f"{state}_{'dirs' if flags & 0x02 else 'files'}"


def record_detail(record: bytes) -> dict[str, int]:
    """One base record's contribution to :data:`DETAIL_KEYS` (``records`` = 1)."""
    repaired, fixup = apply_mft_update_sequence_fixup(record)
    parsed = parse_mft_attributes(repaired, int_from(record, 0x14, 2), int_from(record, 0x18, 4))
    unnamed = [
        item for item in parsed["attributes"] if item.get("attribute_type") == DATA_ATTRIBUTE and not item.get("name")
    ]
    named = [item for item in parsed["attributes"] if item.get("attribute_type") == DATA_ATTRIBUTE and item.get("name")]
    has_attribute_list = "$ATTRIBUTE_LIST" in parsed["attribute_types"]
    link_count = int_from(record, 0x12, 2)
    detail = dict.fromkeys(DETAIL_KEYS, 0)
    detail["records"] = 1
    if unnamed:
        detail["data_nonresident" if unnamed[0].get("nonresident") else "data_resident"] = 1
    elif has_attribute_list:
        detail["data_in_extension_record"] = 1
    else:
        detail["data_absent"] = 1
    detail["ads_streams"] = len(named)
    detail["records_with_ads"] = int(bool(named))
    detail["zone_identifier_streams"] = sum(1 for item in named if str(item.get("name")).lower() == ZONE_IDENTIFIER)
    detail["attribute_list_records"] = int(has_attribute_list)
    # The header link count also counts the 8.3 DOS alias as a link, so a hard link is a record
    # with more than one non-DOS $FILE_NAME (lower bound: names in extension records are not seen).
    non_dos = sum(1 for entry in parsed["file_name_entries"] if entry.get("namespace") != "DOS")
    detail["hard_link_records"] = int(non_dos > 1)
    detail["link_count_total"] = link_count
    detail["non_dos_names"] = non_dos
    detail["fixup_not_applied"] = int(not fixup.get("applied"))
    return detail


def detail_tally(path: Path, *, max_records: int | None = None) -> dict[str, dict[str, int]]:
    totals = {name: dict.fromkeys(DETAIL_KEYS, 0) for name in CLASSES}
    for _number, record in iter_base_records(path, max_records=max_records):
        bucket = totals[record_class(record)]
        for key, value in record_detail(record).items():
            bucket[key] += value
    return totals


def load_extraction_stats(path: Path) -> dict[str, int] | None:
    """Native extraction stats from ``rapidtriage-e01.json`` (``recovered_root_manifest``), the
    stage status file (``command_history`` stage ``native-filesystem-recovery``) or a flat
    ``{files, deleted_files, ...}`` object."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        return None
    stats = _extraction_stats(payload)
    if stats is not None:
        return stats
    history = [
        entry
        for entry in payload.get("command_history") or []
        if isinstance(entry, Mapping) and entry.get("stage") == "native-filesystem-recovery"
    ]
    raw: Mapping[str, Any] = history[-1] if history else payload
    return _extraction_stats({"recovered_root_manifest": {"native_extraction_stats": raw}})


def extraction_table(
    header: Mapping[str, int], detail: Mapping[str, Mapping[str, int]] | None, stats: Mapping[str, int]
) -> list[dict[str, object]]:
    """What the volume holds (``mft``) against what the run wrote (``extracted``) per axis."""
    files = int(stats.get("files") or 0)
    deleted_written = int(stats.get("deleted_files") or 0)
    allocated_copies = max(files - deleted_written, 0)
    names = int(detail["in_use_files"]["non_dos_names"]) if detail else None
    links = int(detail["in_use_files"]["link_count_total"]) if detail else None
    return [
        {
            "axis": "allocated_files",
            "mft": header["in_use_files"],
            "extracted": allocated_copies,
            "mft_non_dos_names": names,
            "mft_link_count_total": links,
            "note_ko": "추출 사본은 하드링크 이름마다 한 개씩 세므로 사용 중 파일 레코드보다 많을 수 있습니다.",
        },
        {
            "axis": "deleted_files",
            "mft": header["deleted_files"],
            "extracted": deleted_written,
            "not_written": max(header["deleted_files"] - deleted_written, 0),
            "reported_truncated": int(stats.get("truncated") or 0),
            "note_ko": "삭제 레코드 중 내용을 쓴 수입니다. 0 채움·덮어씀 판정은 하지 않은 값입니다.",
        },
        {
            "axis": "deleted_dirs",
            "mft": header["deleted_dirs"],
            "extracted": None,
            "note_ko": "추출 통계에 삭제 디렉터리 항목이 없습니다.",
        },
        {
            "axis": "in_use_dirs",
            "mft": header["in_use_dirs"],
            "extracted": None,
            "note_ko": "추출 통계에 디렉터리 항목이 없습니다.",
        },
    ]


def build_report(
    mft: Path, *, e01_json: Path | None = None, header_only: bool = False, max_records: int | None = None
) -> dict[str, object]:
    header = tally_mft_headers(mft)
    detail = None if header_only else detail_tally(mft, max_records=max_records)
    stats = load_extraction_stats(e01_json) if e01_json else None
    table = extraction_table(header, detail, stats) if stats is not None else None
    walk_finished = None
    if stats is not None:
        # The deleted sweep only writes while ``files < file_limit``: if it wrote anything the
        # allocated walk ended below the cap (run_scope rule; inferred until fls/ils).
        walk_finished = stats["deleted_files"] > 0 or 0 < stats["files"] < stats["file_limit"]
    return {
        "schema_version": SCHEMA_VERSION,
        "basis": "inferred",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Counts from a $MFT copy (record headers + base-record attributes). Names held only in "
            "attribute-list extension records are not counted. Confirm with Sleuth Kit ils/fls (T-038)."
        ),
        "inputs": {
            "mft": {"path": str(mft), "size": mft.stat().st_size, "sha256": _sha256(mft)},
            "e01_json": {"path": str(e01_json), "sha256": _sha256(e01_json)} if e01_json else None,
            "max_records": max_records,
        },
        "header": header,
        "detail": detail,
        "extraction_stats": stats,
        "allocated_walk_finished_inferred": walk_finished,
        "extraction_table": table,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _print_summary(report: Mapping[str, Any], output: Path) -> None:
    header = report["header"]
    print(
        f"records {header['records']:,}  in-use files {header['in_use_files']:,}  in-use dirs "
        f"{header['in_use_dirs']:,}  deleted files {header['deleted_files']:,}  deleted dirs "
        f"{header['deleted_dirs']:,}  extension {header['extension_records']:,}  invalid {header['invalid']:,}"
    )
    for name, bucket in (report.get("detail") or {}).items():
        print(
            f"{name}: resident {bucket['data_resident']:,}  non-resident {bucket['data_nonresident']:,}  "
            f"no $DATA {bucket['data_absent']:,}  in extension {bucket['data_in_extension_record']:,}  "
            f"ADS {bucket['ads_streams']:,}  hard-link records {bucket['hard_link_records']:,}"
        )
    for row in report.get("extraction_table") or []:
        print(f"{row['axis']}: mft {row['mft']:,}  extracted {row['extracted'] if row['extracted'] is not None else '-'}")
    print(f"-> {output}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NTFS truth table from a $MFT copy (+ native extraction stats).")
    parser.add_argument("--mft", required=True, type=Path, help="copy of the volume's $MFT")
    parser.add_argument("--e01-json", type=Path, help="rapidtriage-e01.json or _e01/rapidtriage-e01-stage-status.json")
    parser.add_argument("--output", required=True, type=Path, help="report JSON (keep it outside Git)")
    parser.add_argument("--header-only", action="store_true", help="skip the per-record attribute pass")
    parser.add_argument("--max-records", type=int, help="attribute pass over the first N record slots only")
    parser.add_argument("--json", action="store_true", help="print the report JSON")
    args = parser.parse_args(argv)

    report = build_report(args.mft, e01_json=args.e01_json, header_only=args.header_only, max_records=args.max_records)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_summary(report, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
