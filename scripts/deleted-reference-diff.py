#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/deleted-reference-diff.py --ours <run>/rapidtriage-files.json \
#       --reference <fls -rdp [-l] listing | truth CSV> --strip-prefix _e01/fs \
#       [--content-root <dir>] --output <report.json> --json
#
# T-204. Diffs RapidTriage's deleted-file list against a reference deleted list:
#
# * Sleuth Kit `fls -r -d -p` (optionally `-l` for sizes): every deleted, non-directory,
#   non-ADS row is a reference row. Key = volume-relative path (case-insensitive), alias =
#   MFT entry (`inode:<n>`) so lossy ANSI names and `$OrphanFiles` rows still pair.
#   "(realloc)" rows get no entry alias (the entry now holds another file): path only.
#   Compared: size (with -l), and the path of a pair made through the entry alias (a
#   deleted file listed under a wrong folder is a `path` mismatch, not a match) unless the
#   fls name is lossy or the row is under `$OrphanFiles`. `alias_matches` counts them.
# * Truth CSV (the known-answer table): columns `path` (required), optional `inode`,
#   `recoverable`, `sha256`, `content_state`, `size`. Compared: size, the sha256 of rows
#   marked recoverable, and the content state (rapidtriage/core/content_state.py values).
#
# Our list = files-output rows (`candidates` + `inventory`, or a JSONL/JSON array of rows)
# whose `is_deleted` is true, whose recovery block says deleted, or whose candidate kind is
# deleted-entry/orphan-record (`--all-rows` takes every row). Our sha256/content state come
# from the row when present, else from the recovered file (recovery.content_path or path,
# rebased under --content-root when relative), read for rows the reference names and, with
# --content-root, for every row we claim recoverable (matched or extra). Reports zero-filled
# rows we claim recoverable (QA-124: must be 0) over the rows whose content state is known
# (`content_checked`); with no state known it is null ("미측정"), never 0.
#
# Shared loader/diff/report: rapidtriage/validation/reference_diff.py. Exit 0 clean,
# 1 differences, 2 input error. Engineering measurement only; not release evidence.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.content_state import (
    CONTENT_STATES,
    DEFAULT_HEAD_BYTES,
    ZERO_FILLED,
    content_state,
)
from rapidtriage.core.extraction_failures import iter_fls_listing, parse_fls_line
from rapidtriage.core.json_stream import iter_array_items
from rapidtriage.validation import reference_diff as rd

DELETED_KINDS = frozenset({"deleted-entry", "orphan-record"})
DELETED_STATES = frozenset({"deleted", "unallocated", "unallocated-candidate", "orphan"})
REF_PATH = ("path", "fullpath", "originalpath", "filepath", "originalfullpath")
REF_INODE = ("inode", "mftentry", "entrynumber", "mftref", "mftrecord")
REF_RECOVERABLE = ("recoverable", "isrecoverable")
REF_SHA256 = ("sha256", "contentsha256", "hash")
REF_STATE = ("contentstate", "state")
REF_SIZE = ("size", "filesize", "length")


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def is_deleted_row(row: Mapping[str, object]) -> bool:
    recovery = _mapping(row.get("recovery"))
    if row.get("is_deleted") is True or row.get("deleted") is True:
        return True
    states = {str(row.get("deletion_state") or ""), str(recovery.get("deletion_state") or "")}
    return bool(states & DELETED_STATES) or str(recovery.get("candidate_kind") or "") in DELETED_KINDS


def iter_our_rows(path: Path, warnings: list[str]) -> Iterator[Mapping[str, object]]:
    """Files-output ``candidates`` then ``inventory`` (a path seen in both counts once), or plain rows."""
    with path.open("rb") as handle:
        head = handle.read(64).lstrip(b"\xef\xbb\xbf \t\r\n")
    if path.suffix.lower() == ".json" and head.startswith(b"{"):
        seen: set[str] = set()
        for member in ("candidates", "inventory"):
            try:
                for row in iter_array_items(path, member):
                    if isinstance(row, Mapping):
                        key = rd.normalize_path(row.get("path"))
                        if key not in seen:
                            seen.add(key)
                            yield row
            except Exception as exc:  # JsonStreamError: malformed JSON or member not an array
                raise rd.ReferenceDiffInputError(f"우리 파일 목록을 읽지 못했습니다: {path} ({exc})") from exc
        if seen:
            return
    yield from rd.iter_rapid_rows(path, None, warnings)


def our_path(row: Mapping[str, object], strip_prefix: str) -> str:
    recovery = _mapping(row.get("recovery"))
    relative = row.get("relative_path") or recovery.get("original_relative_path")
    if relative:
        return rd.normalize_path(relative, strip_prefix)
    return rd.normalize_path(row.get("path"), strip_prefix)


def our_inode(row: Mapping[str, object]) -> int | None:
    recovery = _mapping(row.get("recovery"))
    for value in (row.get("mft_ref"), row.get("inode"), recovery.get("mft_ref")):
        number = rd.parse_int(value)
        if number is not None:
            return number
    return None


def keys_for(path: str, inode: int | None) -> list[str]:
    keys = [path] if path else []
    if inode is not None:
        keys.append(f"inode:{inode}")
    return keys


def alias_path_field(relative: str, *, lossy: bool) -> str:
    """The reference path compared on a pair made through the entry alias ("" = not compared)."""
    if lossy or not relative or relative.startswith("$orphanfiles/") or "/$orphanfiles/" in relative:
        return ""
    return relative


class ContentProbe:
    """sha256 + content state of our recovered file, read lazily and only for rows the reference names."""

    def __init__(self, content_root: Path | None, warnings: list[str]) -> None:
        self.content_root = content_root
        self.warnings = warnings
        self.unreadable = 0

    def locate(self, row: Mapping[str, object]) -> Path | None:
        recovery = _mapping(row.get("recovery"))
        for raw in (recovery.get("content_path"), row.get("path")):
            if not raw:
                continue
            candidate = Path(str(raw))
            if not candidate.is_absolute() and self.content_root is not None:
                candidate = self.content_root / candidate
            if candidate.is_file():
                return candidate
        return None

    def probe(self, row: Mapping[str, object]) -> tuple[str, str]:
        hashes = _mapping(row.get("hashes"))
        recovery = _mapping(row.get("recovery"))
        sha = str(hashes.get("sha256") or row.get("sha256") or recovery.get("sha256") or "").lower()
        state = str(row.get("content_state") or recovery.get("content_state") or "")
        if sha and state:
            return sha, state
        located = self.locate(row)
        if located is None:
            self.unreadable += 1
            return sha, state
        digest = hashlib.sha256()
        head = b""
        with located.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                if len(head) < DEFAULT_HEAD_BYTES:
                    head += chunk[: DEFAULT_HEAD_BYTES - len(head)]
                digest.update(chunk)
        size = located.stat().st_size
        return sha or digest.hexdigest(), state or content_state(head, size)


def load_fls_reference(path: Path, strip_prefix: str, encoding: str | None, warnings: list[str]) -> tuple[list[rd.KeyedRow], dict[str, int]]:
    stats = {"fls_rows": 0, "allocated_skipped": 0, "directories_skipped": 0, "ads_skipped": 0, "realloc": 0}
    rows: list[rd.KeyedRow] = []
    for entry in iter_fls_listing(path, encoding):
        stats["fls_rows"] += 1
        if not entry.deleted:
            stats["allocated_skipped"] += 1
            continue
        if "d" in (entry.name_type, entry.meta_type):
            stats["directories_skipped"] += 1
            continue
        if entry.is_ads:
            stats["ads_skipped"] += 1
            continue
        stats["realloc"] += int(entry.realloc)
        relative = rd.normalize_path(entry.path, strip_prefix)
        rows.append(
            rd.KeyedRow(
                # A realloc row's entry number now names another file: no alias (review P1-6).
                keys=keys_for(relative, None if entry.realloc else entry.inode),
                fields={"size": entry.size, "path": alias_path_field(relative, lossy=entry.name_lossy)},
                label={"path": relative, "inode": entry.inode, "realloc": entry.realloc, "name_lossy": entry.name_lossy},
            )
        )
    if not stats["fls_rows"]:
        raise rd.ReferenceDiffInputError(f"fls 목록에서 행을 하나도 읽지 못했습니다: {path} (fls -r -d -p 출력인지 확인하세요)")
    if stats["allocated_skipped"] and not rows:
        rd.add_warning(warnings, "fls 목록에 삭제 행(*)이 없습니다: fls -r -d -p 로 다시 뽑으세요")
    return rows, stats


def load_truth_reference(path: Path, strip_prefix: str, warnings: list[str]) -> tuple[list[rd.KeyedRow], dict[str, int]]:
    table, header = rd.read_table(path)
    rd.require_columns(header, path, path=REF_PATH)
    rows: list[rd.KeyedRow] = []
    stats = {"truth_rows": 0, "recoverable": 0}
    for line, row in enumerate(table, start=2):
        relative = rd.normalize_path(rd.pick(row, *REF_PATH), strip_prefix)
        if not relative:
            rd.add_warning(warnings, f"정답표 {line}행에 경로가 없어 건너뛰었습니다")
            continue
        stats["truth_rows"] += 1
        recoverable = rd.parse_bool(rd.pick(row, *REF_RECOVERABLE))
        sha = rd.pick(row, *REF_SHA256).lower()
        state = rd.normalize_text(rd.pick(row, *REF_STATE))
        if state and state not in CONTENT_STATES:
            rd.add_warning(warnings, f"정답표 {line}행 content_state '{state}'는 {', '.join(CONTENT_STATES)} 중 하나가 아닙니다")
        stats["recoverable"] += int(recoverable is True)
        inode = rd.parse_int(rd.pick(row, *REF_INODE))
        rows.append(
            rd.KeyedRow(
                keys=keys_for(relative, inode),
                fields={
                    "size": rd.parse_int(rd.pick(row, *REF_SIZE)),
                    "path": alias_path_field(relative, lossy=False),
                    # Hash agreement is checked for recoverable rows only (no column = trust the hash).
                    "sha256": sha if sha and recoverable is not False else "",
                    "content_state": state,
                },
                label={"path": relative, "inode": inode, "recoverable": recoverable},
            )
        )
    return rows, stats


def is_fls_listing(path: Path) -> bool:
    with path.open("rb") as handle:
        for _, line in zip(range(20), handle):
            if line.strip():
                return parse_fls_line(line, "latin-1") is not None
    return False


def build_deleted_comparison(args: argparse.Namespace, warnings: list[str]) -> rd.Comparison:
    if is_fls_listing(args.reference):
        reference, stats = load_fls_reference(args.reference, args.reference_strip_prefix, args.fls_encoding, warnings)
        tool, compared = "Sleuth Kit fls (-r -d -p)", ["size", "path"]
    else:
        reference, stats = load_truth_reference(args.reference, args.reference_strip_prefix, warnings)
        tool, compared = "known-answer truth CSV", ["size", "sha256", "content_state", "path"]
    wanted = {key for row in reference for key in row.keys}
    needs_content = any(row.fields.get("sha256") or row.fields.get("content_state") for row in reference)
    probe = ContentProbe(args.content_root, warnings)
    ours: list[rd.KeyedRow] = []
    content_checked = claimed_recoverable = 0
    zero_claims: list[str] = []
    for row in iter_our_rows(args.ours, warnings):
        if not args.all_rows and not is_deleted_row(row):
            continue
        keys = keys_for(our_path(row, args.strip_prefix), our_inode(row))
        if not keys:
            continue
        recovery = _mapping(row.get("recovery"))
        claimed = row.get("recoverable") is True or recovery.get("recoverable") is True
        sha, state = ("", str(row.get("content_state") or recovery.get("content_state") or ""))
        if (needs_content and wanted.intersection(keys)) or (claimed and not state and args.content_root is not None):
            sha, state = probe.probe(row)
        claimed_recoverable += int(claimed)
        if state:
            content_checked += 1
            if claimed and state == ZERO_FILLED:
                zero_claims.append(keys[0])
        ours.append(
            rd.KeyedRow(
                keys=keys,
                fields={
                    "size": rd.parse_int(row.get("size")),
                    "sha256": sha,
                    "content_state": state,
                    "path": keys[0] if our_path(row, args.strip_prefix) else "",
                },
                label={"path": keys[0], "inode": our_inode(row)},
            )
        )
    if probe.unreadable:
        rd.add_warning(warnings, f"복구 파일을 읽지 못한 우리 행 {probe.unreadable}개: --content-root를 확인하세요")

    def sections(result: rd.DiffResult) -> dict[str, object]:
        states: dict[str, int] = {}
        alias_matches = 0
        for mine, reference_row in result.matched_pairs:
            state = str(mine.fields.get("content_state") or "")
            if state:
                states[state] = states.get(state, 0) + 1
            alias_matches += int(mine.keys[0] != reference_row.keys[0])
        realloc_matched = sum(1 for _, ref in result.matched_pairs if ref.label.get("realloc"))
        return {
            "reference_stats": stats,
            "alias_matches": alias_matches,
            "realloc_matched_by_path": realloc_matched,
            "our_content_state_counts": dict(sorted(states.items())),
            "content_checked": content_checked,
            "claimed_recoverable": claimed_recoverable,
            # QA-124 "must be 0" is only stated over rows whose content state is known.
            "zero_filled_claimed_recoverable": len(zero_claims) if content_checked else None,
            "zero_filled_claimed_recoverable_status": "measured" if content_checked else "미측정",
            "zero_filled_claimed_recoverable_keys": zero_claims[: max(args.max_list, 0) or None],
        }

    return rd.Comparison(
        ours=ours,
        reference=reference,
        reference_tool=tool,
        key_fields=["path", "inode (alias)"],
        compared_fields=compared,
        extra_sections=sections,
    )


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--strip-prefix", default="", help="cut our paths up to this component run (e.g. _e01/fs)")
    parser.add_argument("--reference-strip-prefix", default="", help="cut reference paths up to this component run")
    parser.add_argument("--content-root", type=Path, help="base folder for relative recovered-content paths")
    parser.add_argument("--fls-encoding", default=None, help="code page of fls names (default: system ANSI, cp949 on Korean Windows)")
    parser.add_argument("--all-rows", action="store_true", help="treat every row of --ours as deleted (pre-filtered list)")


def main(argv: list[str] | None = None) -> int:
    return rd.run_comparison_cli(
        argv,
        comparison="deleted",
        description="Diff RapidTriage's deleted-file list against fls -rdp or a truth CSV (recall, size, sha256, content state).",
        build=build_deleted_comparison,
        configure=configure,
    )


if __name__ == "__main__":
    raise SystemExit(main())
