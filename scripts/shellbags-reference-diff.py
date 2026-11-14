#!/usr/bin/env python3
"""Compare RapidTriage ShellBags with a dedicated ShellBags parser export (T-209).

    python scripts/shellbags-reference-diff.py --ours <run>/artifacts/<per-kind .json or JSONL> \\
        --reference <shellbags.csv> --output <report.json> --json

Key = account + folder path. The account is an explicit account column, else
the ``Users/<name>/`` folder of the hive path, else the SID; it leaves the key
when either side has none (``--ignore-account`` drops it always). Paths are
compared case-insensitively with ``\\`` -> ``/`` and a leading ``Desktop``
segment dropped.

Compared times (UTC whole seconds): BagMRU key last write
(``LastWriteTime``) and the shell item's own created/modified/accessed
times. RapidTriage emits no FirstInteracted value, so "first" is the shell
item's created time (``CreatedOn``).

Ours: ``shellbag-entry`` rows (``shell_path``, ``key_last_written_at``,
``item_created_at``/``item_modified_at``/``item_accessed_at``, ``user_sid``,
``source_path``); BagMRU root rows are skipped. Reference: CSV/TSV such as
SBECmd/ShellBags Explorer (``AbsolutePath``, ``LastWriteTime``,
``CreatedOn``, ``ModifiedOn``, ``AccessedOn``, ``SourceFile``).

Shared loader/diff/report: rapidtriage/validation/reference_diff.py.
Exit 0 clean, 1 differences, 2 input error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.validation import reference_diff as rd

SHELLBAG_ARTIFACT_TYPES = ("shellbag-entry",)
REF_PATH = ("absolutepath", "path", "folderpath", "shellpath")
REF_ACCOUNT = ("account", "user", "username")
REF_HIVE = ("sourcefile", "hivepath", "source")
REF_SID = ("usersid", "sid")
REF_TIMES = {
    "last_written": ("lastwritetime", "lastwrite", "keylastwrittenat"),
    "item_created": ("createdon", "created", "itemcreatedat"),
    "item_modified": ("modifiedon", "modified", "itemmodifiedat"),
    "item_accessed": ("accessedon", "accessed", "itemaccessedat"),
}
OURS_TIMES = {
    "last_written": "key_last_written_at",
    "item_created": "item_created_at",
    "item_modified": "item_modified_at",
    "item_accessed": "item_accessed_at",
}
_PROFILE_RE = re.compile(r"(?:^|/)(?:users|documents and settings)/([^/]+)/")


def shell_path_key(value: object) -> str:
    text = rd.normalize_text(str(value or "").strip().strip('"').replace("\\", "/"))
    text = re.sub(r"/{2,}", "/", text).strip("/")
    return re.sub(r"^desktop/", "", text)


def account_name(explicit: object, hive_path: object, sid: object) -> str:
    """Explicit account, else ``Users/<name>/`` of the hive path, else the SID; ``""`` when unknown."""
    text = rd.normalize_text(explicit)
    if text:
        return text
    match = _PROFILE_RE.search(rd.normalize_path(hive_path) + "/")
    return match.group(1) if match else rd.normalize_text(sid)


def bag_row(account: str, path: str, times: dict[str, object]) -> rd.KeyedRow:
    return rd.KeyedRow(keys=[f"{account}|{path}"], fields=dict(times), label={"account": account, "path": path, **times})


def build_shellbags_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    table, header = rd.read_table(args.reference)
    rd.require_columns(header, args.reference, path=REF_PATH)
    reference: list[rd.KeyedRow] = []
    for line, row in enumerate(table, start=2):
        path = shell_path_key(rd.pick(row, *REF_PATH))
        if not path:
            rd.add_warning(warnings, f"기준 {line}행에 폴더 경로가 없어 건너뛰었습니다")
            continue
        account = account_name(rd.pick(row, *REF_ACCOUNT), rd.pick(row, *REF_HIVE), rd.pick(row, *REF_SID))
        times = {
            name: rd.safe_timestamp(rd.pick(row, *aliases), args.reference_tzinfo, warnings, f"기준 {line}행")
            for name, aliases in REF_TIMES.items()
        }
        reference.append(bag_row(account, path, times))
    ours: list[rd.KeyedRow] = []
    for row in rd.iter_rapid_rows(args.ours, SHELLBAG_ARTIFACT_TYPES, warnings):
        path = shell_path_key(rd.rapid_field(row, "shell_path", "absolute_path"))
        if not path or rd.rapid_field(row, "bagmru_root") is True:
            continue
        account = account_name(
            rd.rapid_field(row, "account", "user_name", "username"),
            rd.rapid_field(row, "source_path", "hive_mount", "path"),
            rd.rapid_field(row, "user_sid"),
        )
        times = {
            name: rd.safe_timestamp(rd.rapid_field(row, field), args.ours_tzinfo, warnings, "우리 ShellBags 행")
            for name, field in OURS_TIMES.items()
        }
        ours.append(bag_row(account, path, times))
    key_fields = ["account", "folder_path"]
    if args.ignore_account or rd.drop_blank_key_part(ours, reference, 0):
        if args.ignore_account:
            for item in (*ours, *reference):
                item.keys = [key.split("|", 1)[1] for key in item.keys]
        else:
            rd.add_warning(warnings, "한쪽에 계정 값이 없어 키에서 계정을 뺐습니다")
        key_fields = ["folder_path"]
    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool="ShellBags parser (CSV)",
        key_fields=key_fields,
        compared_fields=list(REF_TIMES),
    )


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="shellbags",
        description="Diff RapidTriage shellbag-entry rows against a ShellBags parser CSV (key = account + path).",
        build=build_shellbags_comparison,
        configure=lambda parser: parser.add_argument(
            "--ignore-account", action="store_true", help="key on the folder path only"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
