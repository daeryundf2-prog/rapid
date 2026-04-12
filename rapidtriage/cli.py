from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

from .core.artifacts import ArtifactCollectionError, SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .core.docs import build_manifest, run_docs_search, write_result
from .core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, SUPPORTED_DOC_KINDS, run_extract
from .core.files import ALL_FILE_CATEGORIES, FileScanError, run_files_scan
from .core.input_root import SUPPORTED_INPUT_ROOT_KINDS
from .core.run import RunModeError, SUPPORTED_RUN_MODES, run_triage_mode

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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage manifest . --output rapidtriage-manifest.json
              rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
              rapidtriage files . --output rapidtriage-files.json
              rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
              rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
              rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage manifest /Volumes/case-mount --input-kind mounted-image
              rapidtriage run . --mode fraud --output-dir ./rapidtriage-run
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    docs = sub.add_parser(
        "docs",
        help="Search document bodies for keywords and save JSON output",
        description="Search document bodies for keywords and save JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
              rapidtriage docs /cases/image-mount -k password --limit 250 --output docs-hits.json
            """
        ),
    )
    docs.add_argument("root", help="Directory to scan")
    docs.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    docs.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    docs.add_argument("--output", default="rapidtriage-docs.json", help="JSON output path")
    docs.add_argument("--limit", type=int, default=0, help="Stop after scanning N candidates (0 means all)")

    manifest = sub.add_parser(
        "manifest",
        help="Write provider manifest JSON",
        description="Write provider manifest JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage manifest . --output rapidtriage-manifest.json
              rapidtriage manifest /cases/image-mount --output case-manifest.json
            """
        ),
    )
    manifest.add_argument("root", help="Directory to describe")
    manifest.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    manifest.add_argument("--output", default="rapidtriage-manifest.json", help="JSON output path")

    artifacts = sub.add_parser(
        "artifacts",
        help="Run a dedicated artifact collector and save JSON output",
        description="Run a dedicated artifact collector and save JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage artifacts /cases/image-mount --kind recent-files
            """
        ),
    )
    artifacts.add_argument("root", nargs="?", default=".", help="Directory to scan (default: current directory)")
    artifacts.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    artifacts.add_argument("--kind", required=True, choices=sorted(SUPPORTED_ARTIFACT_KINDS), help="Artifact collector kind")
    artifacts.add_argument("--output", help="JSON output path (default: ./rapidtriage-artifacts-KIND.json)")

    files = sub.add_parser(
        "files",
        help="Scan file metadata for likely forensic candidates and save JSON output",
        description="Scan file metadata for likely forensic candidates and save JSON output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage files . --output rapidtriage-files.json
              rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
              rapidtriage files . --name-contains note --path-contains desktop --output desktop-notes.json
            """
        ),
    )
    files.add_argument("root", help="Directory to scan")
    files.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    files.add_argument("--output", default="rapidtriage-files.json", help="JSON output path")
    files.add_argument("--limit", type=int, default=0, help="Stop after collecting N candidates (0 means all)")
    files.add_argument(
        "--category",
        action="append",
        choices=sorted(ALL_FILE_CATEGORIES),
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
        description="Copy files referenced by files/docs JSON into an output directory and save a manifest JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
              rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf --manifest ./docs-out/rapidtriage-extract-manifest.json
            """
        ),
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
        choices=sorted(ALL_FILE_CATEGORIES),
        help="Only for files JSON: restrict extracted candidates by category",
    )
    extract.add_argument(
        "--kind",
        action="append",
        choices=sorted(SUPPORTED_DOC_KINDS),
        help="Only for docs JSON: restrict extracted matches by document kind",
    )

    run = sub.add_parser(
        "run",
        help="Run an incident-mode triage workflow and write summary/report outputs",
        description="Run an incident-mode triage workflow and write summary/report outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage run . --mode fraud
              rapidtriage run /cases/image-mount --mode seizure --output-dir ./rapidtriage-run
              rapidtriage run /cases/image-mount --mode recovery --output-dir ./rapidtriage-run-recovery
            """
        ),
    )
    run.add_argument("root", help="Directory to triage")
    run.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    run.add_argument("--mode", required=True, choices=sorted(SUPPORTED_RUN_MODES), help="Incident mode to execute")
    run.add_argument(
        "--output-dir",
        help="Directory that receives the generated JSON, extract manifests, and execution report "
        "(default: ROOT/rapidtriage-run-MODE)",
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
    if args.command == "run":
        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else root / f"rapidtriage-run-{args.mode.lower()}"
        )
        try:
            payload = run_triage_mode(root, mode=args.mode, output_dir=output_dir, input_kind=args.input_kind)
        except RunModeError as exc:
            parser.error(str(exc))
        print(f"Saved run summary JSON: {payload['outputs']['summary']}")
        print(f"Saved run report: {payload['outputs']['report']}")
        print(
            f"Docs matches: {payload['summary']['document_match_count']}  "
            f"File candidates: {payload['summary']['file_candidate_count']}"
        )
        return 0

    if args.command == "artifacts":
        output = (
            Path(args.output).expanduser().resolve()
            if args.output
            else (Path.cwd() / f"rapidtriage-artifacts-{args.kind}.json").resolve()
        )
        try:
            payload = run_artifact_collection(root, kind=args.kind, input_kind=args.input_kind)
        except ArtifactCollectionError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        print(f"Saved artifact collector JSON: {output}")
        print(f"Kind: {payload['kind']}  Artifacts: {payload['summary']['artifact_count']}")
        return 0

    output = Path(args.output).expanduser().resolve()

    if args.command == "docs":
        payload = run_docs_search(root, args.keyword, limit=args.limit, input_kind=args.input_kind)
        write_result(payload, output)
        print(f"Saved docs search JSON: {output}")
        print(f"Candidates: {payload['summary']['candidate_count']}  Matches: {payload['summary']['match_count']}")
        return 0

    if args.command == "manifest":
        payload = build_manifest(root, [], input_kind=args.input_kind)
        write_result(payload, output)
        print(f"Saved manifest JSON: {output}")
        return 0

    if args.command == "files":
        try:
            payload = run_files_scan(
                root,
                input_kind=args.input_kind,
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
