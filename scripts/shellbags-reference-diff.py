#!/usr/bin/env python3
"""Compare RapidTriage ShellBags with a dedicated ShellBags parser export (T-209).

    python scripts/shellbags-reference-diff.py --ours <records.jsonl> \\
        --reference <shellbags.csv> --output <report.json> --json

Key = account + folder path. The account is an explicit account column, else
the ``\\Users\\<name>\\`` segment of the hive path, else the SID
(``--ignore-account`` keys on the path alone for single-user hives). Paths
are compared case-insensitively with ``/`` -> ``\\`` and a leading
``Desktop\\`` segment dropped.

Compared times (UTC seconds): BagMRU key last write (``LastWriteTime``)
and the shell item's own created/modified/accessed times. RapidTriage does
not emit a FirstInteracted value, so "first" is the shell item's created
time (``CreatedOn``).

Ours: ``shellbag-entry`` records (``shell_path``, ``key_last_written_at``,
``item_created_at``/``item_modified_at``/``item_accessed_at``, ``user_sid``,
``source_path``). Reference: CSV/TSV such as SBECmd/ShellBags Explorer
(``AbsolutePath``, ``LastWriteTime``, ``CreatedOn``, ``ModifiedOn``,
``AccessedOn``, ``SourceFile``).

Report keys: recall, matched, missing, mismatched, reference_tool (+ extra,
counts). Exit 2 when an input is missing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _wc5_helpers as H

OURS_TYPES = {"shellbag-entry"}
PATH_OURS = ("shell_path", "absolute_path")
PATH_REF = ("AbsolutePath", "Absolute Path", "Path", "FolderPath", "Folder Path", "shell_path")
ACCOUNT_OURS = ("account", "user_name", "username")
ACCOUNT_REF = ("Account", "User", "UserName", "User Name")
HIVE_OURS = ("source_path", "hive_mount", "path")
HIVE_REF = ("SourceFile", "Source File", "HivePath", "Hive Path", "Source")
SID_OURS = ("user_sid",)
SID_REF = ("UserSid", "User SID", "SID")


def norm_shell_path(value: object) -> str:
    text = H.norm_path(value)
    return re.sub(r"^desktop\\", "", text)


def _account(row, explicit, hive, sid) -> str:
    named = H.norm_text(H.pick(row, explicit))
    if named:
        return named
    from_path = H.account_from_path(H.pick(row, hive))
    return from_path or H.norm_text(H.pick(row, sid))


def key_fn(paths, explicit, hive, sid, ignore_account: bool):
    def key(row) -> str:
        path = norm_shell_path(H.pick(row, paths))
        if not path:
            return ""
        return path if ignore_account else f"{_account(row, explicit, hive, sid)}|{path}"

    return key


def fields(naive_tz) -> list[H.FieldSpec]:
    def ts(value: object) -> str:
        return H.norm_ts(value, naive_tz)

    return [
        H.FieldSpec("last_written", ("key_last_written_at",),
                    ("LastWriteTime", "Last Write Time", "LastWrite", "key_last_written_at"), ts),
        H.FieldSpec("item_created", ("item_created_at",), ("CreatedOn", "Created On", "Created", "item_created_at"), ts),
        H.FieldSpec("item_modified", ("item_modified_at",),
                    ("ModifiedOn", "Modified On", "Modified", "item_modified_at"), ts),
        H.FieldSpec("item_accessed", ("item_accessed_at",),
                    ("AccessedOn", "Accessed On", "Accessed", "item_accessed_at"), ts),
    ]


def compare(ours_rows, reference_rows, naive_tz, *, ignore_account: bool = False) -> dict[str, object]:
    ours_rows = [
        row
        for row in ours_rows
        if str(row.get("artifact_type") or "") in OURS_TYPES and not row.get("bagmru_root")
    ]
    return H.diff_keyed(
        ours_rows,
        reference_rows,
        ours_key=key_fn(PATH_OURS, ACCOUNT_OURS, HIVE_OURS, SID_OURS, ignore_account),
        reference_key=key_fn(PATH_REF, ACCOUNT_REF, HIVE_REF, SID_REF, ignore_account),
        fields=fields(naive_tz),
    )


def main(argv: list[str] | None = None) -> int:
    parser = H.base_parser(__doc__.splitlines()[0], "shellbags-parser-csv")
    parser.add_argument("--ignore-account", action="store_true", help="key on the folder path only")

    def body() -> int:
        args = parser.parse_args(argv)
        H.require_inputs({"--ours": args.ours, "--reference": args.reference})
        naive_tz = H.parse_tz(args.reference_tz)
        result = compare(
            H.load_ours(args.ours), H.load_csv(args.reference), naive_tz, ignore_account=args.ignore_account
        )
        report = H.envelope(
            "shellbags", args.reference_tool, {"ours": args.ours, "reference": args.reference}, result
        )
        return H.emit(report, args.output, args.json, H.summary_line(report))

    return H.run_cli(body)


if __name__ == "__main__":
    raise SystemExit(main())
