from __future__ import annotations

import argparse
from pathlib import Path

from .core.docs import build_manifest, run_docs_search, write_result
from .core.files import DEFAULT_FILE_CATEGORIES, FileScanError, run_files_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapidtriage",
        description="Lightweight forensic triage CLI with OS-independent core and pluggable artifact providers",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    docs = sub.add_parser("docs", help="Search document bodies for keywords and save JSON output")
    docs.add_argument("root", help="Directory to scan")
    docs.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    docs.add_argument("--output", default="rapidtriage-docs.json", help="JSON output path")
    docs.add_argument("--limit", type=int, default=0, help="Stop after scanning N candidates (0 means all)")

    manifest = sub.add_parser("manifest", help="Write provider manifest JSON")
    manifest.add_argument("root", help="Directory to describe")
    manifest.add_argument("--output", default="rapidtriage-manifest.json", help="JSON output path")

    files = sub.add_parser("files", help="Scan file metadata for likely forensic candidates and save JSON output")
    files.add_argument("root", help="Directory to scan")
    files.add_argument("--output", default="rapidtriage-files.json", help="JSON output path")
    files.add_argument("--limit", type=int, default=0, help="Stop after collecting N candidates (0 means all)")
    files.add_argument(
        "--category",
        action="append",
        choices=sorted(DEFAULT_FILE_CATEGORIES),
        help="Restrict categories (repeatable; defaults to all built-in categories)",
    )
    files.add_argument("--name-contains", action="append", help="Only keep files whose basename contains this text")
    files.add_argument("--path-contains", action="append", help="Only keep files whose path contains this text")
    files.add_argument("--ext", action="append", help="Only keep files with this extension (repeatable)")
    files.add_argument("--modified-after", help="Only keep files modified at or after this ISO timestamp/date")
    files.add_argument("--modified-before", help="Only keep files modified at or before this ISO timestamp/date")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()

    if args.command == "docs":
        payload = run_docs_search(root, args.keyword, limit=args.limit)
        write_result(payload, output)
        print(f"Saved docs search JSON: {output}")
        print(f"Candidates: {payload['summary']['candidate_count']}  Matches: {payload['summary']['match_count']}")
        return 0

    if args.command == "manifest":
        payload = build_manifest(root, [])
        write_result(payload, output)
        print(f"Saved manifest JSON: {output}")
        return 0

    if args.command == "files":
        try:
            payload = run_files_scan(
                root,
                categories=args.category,
                name_contains=args.name_contains,
                path_contains=args.path_contains,
                extensions=args.ext,
                modified_after=args.modified_after,
                modified_before=args.modified_before,
                limit=args.limit,
            )
        except FileScanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        print(f"Saved file scan JSON: {output}")
        print(f"Scanned: {payload['summary']['scanned_file_count']}  Candidates: {payload['summary']['candidate_count']}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
