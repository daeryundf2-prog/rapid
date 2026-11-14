#!/usr/bin/env python3
"""Compare RapidTriage Recycle Bin entries with a direct ``$I`` decode (T-211).

    python scripts/recyclebin-reference-diff.py --ours <records.jsonl> \\
        --reference <rbcmd.csv> --output <report.json> --json

Key = ``$I`` file name (case-insensitive). Compared: original path
(case-insensitive), deleted file size and deletion time (UTC seconds).

Ours: ``recycle-bin-entry`` records (``source_path``/``path`` ending in the
``$I`` name, ``original_path``, ``deleted_file_size``, ``deleted_at``).
Reference: CSV/TSV from a direct ``$I`` parser such as RBCmd
(``SourceName``, ``FileName``, ``FileSize``, ``DeletedOn``) or an equivalent
hand decode (``i_file``, ``original_path``, ``size``, ``deleted_at``).

Report keys: recall, matched, missing, mismatched, reference_tool (+ extra,
counts). Exit 2 when an input is missing.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

OURS_TYPES = {"recycle-bin-entry"}
I_FILE_OURS = ("source_path", "path")
I_FILE_REF = ("SourceName", "Source Name", "i_file", "$I File", "IFile", "source_path", "SourceFile")


def i_name(value: object) -> str:
    name = H.norm_path(value).rsplit("\\", 1)[-1]
    return name if name.startswith("$i") else ""


def ours_key(row) -> str:
    name = i_name(H.pick(row, I_FILE_OURS))
    if name:
        return name
    recycle_id = str(row.get("recycle_id") or "").strip().casefold()
    return f"$i{recycle_id}" if recycle_id else ""


def fields(naive_tz) -> list[H.FieldSpec]:
    def ts(value: object) -> str:
        return H.norm_ts(value, naive_tz)

    return [
        H.FieldSpec("original_path", ("original_path",),
                    ("FileName", "File Name", "OriginalPath", "Original Path", "original_path"), H.norm_path),
        H.FieldSpec("size", ("deleted_file_size",),
                    ("FileSize", "File Size", "Size", "deleted_file_size"), H.norm_int),
        H.FieldSpec("deleted_at", ("deleted_at",),
                    ("DeletedOn", "Deleted On", "DeletedTime", "Deleted Time", "deleted_at"), ts),
    ]


def compare(ours_rows, reference_rows, naive_tz) -> dict[str, object]:
    ours_rows = [row for row in ours_rows if str(row.get("artifact_type") or "") in OURS_TYPES]
    return H.diff_keyed(
        ours_rows,
        reference_rows,
        ours_key=ours_key,
        reference_key=lambda row: i_name(H.pick(row, I_FILE_REF)),
        fields=fields(naive_tz),
    )


def main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(__doc__.splitlines()[0], "recyclebin-i-file-parser-csv")

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference})
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare(H.load_ours(args.ours), H.load_csv(args.reference), naive_tz)
        report = H.envelope(
            "recycle-bin", args.reference_tool, {"ours": args.ours, "reference": args.reference}, result
        )
        return H.emit(report, args.output, args.json, H.summary_line(report))

    return H.run_cli(body)


if __name__ == "__main__":
    raise SystemExit(main())
