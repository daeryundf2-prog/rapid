from __future__ import annotations

import argparse
from pathlib import Path

from .core.docs import build_manifest, run_docs_search, write_result
from .core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, SUPPORTED_DOC_KINDS, run_extract
from .core.files import DEFAULT_FILE_CATEGORIES, FileScanError, run_files_scan

HELP_FORMATTER = argparse.RawDescriptionHelpFormatter
TOP_LEVEL_EPILOG = """Examples:
  rapidtriage manifest . --output rapidtriage-manifest.json
  rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
  rapidtriage files . --category documents --ext docx --modified-after 2025-01-01
  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
"""
MANIFEST_EPILOG = """Examples:
  rapidtriage manifest .
  rapidtriage manifest /cases/image-mount --output case-manifest.json
"""
DOCS_EPILOG = """Examples:
  rapidtriage docs . -k incident -k registry
  rapidtriage docs /cases/image-mount -k password --limit 250 --output docs-hits.json
"""
FILES_EPILOG = """Examples:
  rapidtriage files .
  rapidtriage files /cases/image-mount --category executables --ext exe --modified-after 2025-01-01
  rapidtriage files . --name-contains note --path-contains desktop --output desktop-notes.json
"""
EXTRACT_EPILOG = f"""Examples:
  rapidtriage extract rapidtriage-files.json ./extract-out
  rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf --manifest ./docs-out/{DEFAULT_EXTRACT_MANIFEST_NAME}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapidtriage",
        description="Lightweight forensic triage CLI with OS-independent core and pluggable artifact providers",
        epilog=(
            "Examples:\n"
            "  rapidtriage manifest . --output rapidtriage-manifest.json\n"
            "  rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json\n"
            "  rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 "
            "--output recent-executables.json\n"
            "  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    docs = sub.add_parser(
        "docs",
        help="Search document bodies for keywords and save JSON output",
        epilog=(
            "Examples:\n"
            "  rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json\n"
            "  rapidtriage docs ./evidence -k credential --limit 25 --output hits.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    docs.add_argument("root", help="Directory to scan")
    docs.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    docs.add_argument("--output", default="rapidtriage-docs.json", help="JSON output path")
    docs.add_argument("--limit", type=int, default=0, help="Stop after scanning N candidates (0 means all)")

    manifest = sub.add_parser(
        "manifest",
        help="Write provider manifest JSON",
        epilog=(
            "Examples:\n"
            "  rapidtriage manifest . --output rapidtriage-manifest.json\n"
            "  rapidtriage manifest /mnt/evidence --output provider-manifest.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    manifest.add_argument("root", help="Directory to describe")
    manifest.add_argument("--output", default="rapidtriage-manifest.json", help="JSON output path")

    files = sub.add_parser(
        "files",
        help="Scan file metadata for likely forensic candidates and save JSON output",
        epilog=(
            "Examples:\n"
            "  rapidtriage files . --output rapidtriage-files.json\n"
            "  rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 "
            "--output recent-executables.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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

    extract = sub.add_parser(
        "extract",
        help="Copy files referenced by files/docs JSON into an output directory and save a manifest JSON",
        epilog=(
            "Examples:\n"
            "  rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt\n"
            "  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    extract.add_argument("input_json", help="Path to rapidtriage files/docs JSON")
    extract.add_argument("output_dir", help="Directory to copy matching files into")
    extract.add_argument(
        "--manifest",
        help=f"Manifest JSON output path (default: OUTPUT_DIR/{DEFAULT_EXTRACT_MANIFEST_NAME})",
    )
    extract.add_argument("--limit", type=int, default=0, help="Stop after extracting N matching files (0 means all)")
    extract.add_argument("--name-contains", action="append", help="Only extract files whose basename contains this text")
    extract.add_argument("--path-contains", action="append", help="Only extract files whose path contains this text")
    extract.add_argument("--ext", action="append", help="Only extract files with this extension (repeatable)")
    extract.add_argument(
        "--category",
        action="append",
        choices=sorted(DEFAULT_FILE_CATEGORIES),
        help="Only for files JSON: restrict extracted candidates by category",
    )
    extract.add_argument(
        "--kind",
        action="append",
        choices=sorted(SUPPORTED_DOC_KINDS),
        help="Only for docs JSON: restrict extracted matches by document kind",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        input_json = Path(args.input_json).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        manifest_output = (
            Path(args.manifest).expanduser().resolve()
            if args.manifest
            else output_dir / DEFAULT_EXTRACT_MANIFEST_NAME
        )
        try:
            payload = run_extract(
                input_json,
                output_dir,
                name_contains=args.name_contains,
                path_contains=args.path_contains,
                extensions=args.ext,
                categories=args.category,
                kinds=args.kind,
                limit=args.limit,
            )
        except ExtractError as exc:
            parser.error(str(exc))
        write_result(payload, manifest_output)
        print(f"Saved extract manifest JSON: {manifest_output}")
        print(f"Selected: {payload['summary']['selected_count']}  Extracted: {payload['summary']['extracted_count']}")
        return 0

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
