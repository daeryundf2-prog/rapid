#!/usr/bin/env python3
"""Compare RapidTriage Recycle Bin entries with a direct ``$I`` decode (T-211).

    python scripts/recyclebin-reference-diff.py --ours <run>/artifacts/<per-kind .json or JSONL> \\
        --reference <rbcmd.csv> --output <report.json> --json

Key = ``$I`` file name (case-insensitive). Compared: original path
(case-insensitive, drive letter kept), deleted file size and deletion time
(UTC whole seconds).

Ours: ``recycle-bin-entry`` rows (``source_path``/``path`` ending in the
``$I`` name, else ``recycle_id``; ``original_path``, ``deleted_file_size``,
``deleted_at``). Reference: CSV/TSV from a direct ``$I`` parser such as
RBCmd (``SourceName``, ``FileName``, ``FileSize``, ``DeletedOn``) or an
equivalent hand decode (``i_file``, ``original_path``, ``size``,
``deleted_at``).

Shared loader/diff/report: rapidtriage/validation/reference_diff.py.
Exit 0 clean, 1 differences, 2 input error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

RECYCLE_ARTIFACT_TYPES = ("recycle-bin-entry",)
REF_I_FILE = ("sourcename", "ifile", "sourcepath", "sourcefile")
REF_ORIGINAL = ("filename", "originalpath")
REF_SIZE = ("filesize", "size", "deletedfilesize")
REF_DELETED = ("deletedon", "deletedtime", "deletedat")


def i_name(value: object) -> str:
    name = rd.normalize_text(str(value or "").replace("\\", "/")).rsplit("/", 1)[-1]
    return name if name.startswith("$i") else ""


def original_path(value: object) -> str:
    return rd.normalize_text(str(value or "").strip().strip('"').replace("/", "\\"))


def recycled_row(name: str, original: object, size: int | None, deleted: object) -> rd.KeyedRow:
    fields = {"original_path": original_path(original), "size": size, "deleted_at": deleted}
    return rd.KeyedRow(keys=[name], fields=fields, label={"i_file": name, **fields})


def build_recyclebin_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, i_file=REF_I_FILE)
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        name = i_name(rd.pick(row, *REF_I_FILE))
        if not name:
            rd.add_warning(warnings, f"기준 {line}행에 $I 파일 이름이 없어 건너뛰었습니다")
            continue
        deleted = rd.safe_timestamp(rd.pick(row, *REF_DELETED), args.reference_tzinfo, warnings, f"기준 {line}행")
        reference.append(
            recycled_row(name, rd.pick(row, *REF_ORIGINAL), rd.parse_int(rd.pick(row, *REF_SIZE)), deleted)
        )
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, RECYCLE_ARTIFACT_TYPES, warnings):
        name = i_name(rd.rapid_field(row, "source_path", "path"))
        if not name:
            recycle_id = rd.normalize_text(rd.rapid_field(row, "recycle_id"))
            name = f"$i{recycle_id}" if recycle_id else ""
        if not name:
            continue
        deleted = rd.safe_timestamp(rd.rapid_field(row, "deleted_at"), args.ours_tzinfo, warnings, "우리 휴지통 행")
        ours.append(
            recycled_row(
                name,
                rd.rapid_field(row, "original_path"),
                rd.parse_int(rd.rapid_field(row, "deleted_file_size")),
                deleted,
            )
        )
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool="Recycle Bin $I parser (CSV)",
        key_fields=["i_file"],
        compared_fields=["original_path", "size", "deleted_at"],
    )


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="recycle-bin",
        description="Diff RapidTriage recycle-bin-entry rows against a direct $I decode CSV (key = $I name).",
        build=build_recyclebin_comparison,
    )


if __name__ == "__main__":
    raise SystemExit(main())
