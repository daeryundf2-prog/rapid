from __future__ import annotations

import argparse
import json
import textwrap
from pathlib import Path

from .core.audit import audit_path_for, write_audit_record
from .core.artifacts import ArtifactCollectionError, SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .core.case import CaseBookmarkError, create_or_update_case_payload, load_case_payload, save_case_payload
from .core.docs import build_manifest, run_docs_search, write_result
from .core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, SUPPORTED_DOC_KINDS, run_extract
from .core.files import ALL_FILE_CATEGORIES, FileScanError, run_files_scan
from .core.input_root import SUPPORTED_INPUT_ROOT_KINDS, resolve_input_root
from .core.rules import RuleConfigError, load_rule_set
from .core.run import RunModeError, SUPPORTED_RUN_MODES, run_triage_mode
from .core.timeline import TimelineError, build_timeline_report, run_timeline

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
  rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
"""


def add_rules_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", help="Path to a rapidtriage JSON/YAML rule file for matched_rules and IOC lookup")


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
              rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage timeline . --output rapidtriage-timeline.json --report rapidtriage-timeline-report.md
              rapidtriage case ./incident-case.json --source rapidtriage-timeline.json --pointer /events/0 --tag suspicious
              rapidtriage manifest /Volumes/case-mount --input-kind mounted-image
              rapidtriage run . --mode fraud --output-dir ./rapidtriage-run --read-only
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
    add_rules_argument(docs)

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
    add_rules_argument(artifacts)

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
    add_rules_argument(files)

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
              rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-extract-size-bytes 104857600
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
    extract.add_argument("--dry-run", action="store_true", help="Select files and write manifest without copying evidence")
    extract.add_argument("--read-only", action="store_true", help="Do not copy source files; only record what would be extracted")
    extract.add_argument("--max-extract-size-bytes", type=int, default=0, help="Stop copying when total extracted bytes would exceed this value (0 means unlimited)")
    extract.add_argument("--max-file-count", type=int, default=0, help="Maximum number of files to copy (0 means unlimited)")
    extract.add_argument("--overwrite", action="store_true", help="Allow overwriting existing output files")

    timeline = sub.add_parser(
        "timeline",
        help="Merge files/docs/artifacts JSON outputs into a time-ordered timeline and Markdown report",
        description="Merge files/docs/artifacts JSON outputs into a time-ordered timeline and Markdown report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage timeline .
              rapidtriage timeline /cases/image-mount --output rapidtriage-timeline.json --report rapidtriage-timeline-report.md
              rapidtriage timeline . --files rapidtriage-files.json --docs rapidtriage-docs.json --artifacts ./browser.json --artifacts ./recent.json
            """
        ),
    )
    timeline.add_argument("root", nargs="?", default=".", help="Directory to scan (default: current directory)")
    timeline.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    timeline.add_argument("--files", action="append", help="Path to a rapidtriage files JSON output (repeatable)")
    timeline.add_argument("--docs", action="append", help="Path to a rapidtriage docs JSON output (repeatable)")
    timeline.add_argument("--artifacts", action="append", help="Path to a rapidtriage artifacts JSON output (repeatable)")
    timeline.add_argument("--output", default="rapidtriage-timeline.json", help="Timeline JSON output path")
    timeline.add_argument("--report", help="Markdown report output path (default: OUTPUT stem + -report.md)")
    add_rules_argument(timeline)

    case_parser = sub.add_parser(
        "case",
        help="Save or load case-level bookmarks from rapidtriage JSON outputs",
        description="Save or load case-level bookmarks from rapidtriage JSON outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case ./incident-case.json
              rapidtriage case ./incident-case.json --source rapidtriage-timeline.json --pointer /events/0 --tag suspicious --note "Review this event"
              rapidtriage case ./incident-case.json --source rapidtriage-files.json --pointer /candidates/1 --bookmark-id loader --tag executable
              rapidtriage case ./incident-case.json --show
            """
        ),
    )
    case_parser.add_argument("case_json", help="Path to the case JSON to create/update/load")
    case_parser.add_argument("--case-id", help="Stable case identifier (default: CASE_JSON stem when creating)")
    case_parser.add_argument("--title", help="Human-readable case title")
    case_parser.add_argument("--source", help="Path to a rapidtriage JSON output to bookmark from")
    case_parser.add_argument("--pointer", help="JSON Pointer to the selected row inside --source (for example /events/0)")
    case_parser.add_argument("--bookmark-id", help="Optional stable bookmark identifier for updates")
    case_parser.add_argument("--tag", action="append", help="Bookmark tag (repeatable)")
    case_parser.add_argument("--note", help="Bookmark note text")
    case_parser.add_argument("--show", action="store_true", help="Load an existing case JSON and print it to stdout")

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
              rapidtriage run . --mode hacking --read-only --max-file-count 50
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
    run.add_argument("--dry-run", action="store_true", help="Skip evidence copying during extract stages")
    run.add_argument("--read-only", action="store_true", help="Run triage without copying evidence files during extract stages")
    run.add_argument("--max-extract-size-bytes", type=int, default=0, help="Cap total copied bytes per extract stage (0 means unlimited)")
    run.add_argument("--max-file-count", type=int, default=0, help="Cap copied files per extract stage (0 means unlimited)")
    run.add_argument("--overwrite", action="store_true", help="Allow extract stages to overwrite existing output files")
    add_rules_argument(run)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    rule_set = None
    if getattr(args, "rules", None):
        try:
            rule_set = load_rule_set(Path(args.rules).expanduser().resolve())
        except (FileNotFoundError, OSError, json.JSONDecodeError, RuleConfigError) as exc:
            parser.error(f"invalid rules file: {exc}")

    if args.command == "case":
        case_path = Path(args.case_json).expanduser().resolve()
        if args.show:
            try:
                payload = load_case_payload(case_path)
            except (FileNotFoundError, CaseBookmarkError) as exc:
                parser.error(str(exc))
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0

        source_path = Path(args.source).expanduser().resolve() if args.source else None
        try:
            payload = create_or_update_case_payload(
                case_path,
                case_id=args.case_id,
                title=args.title,
                source_path=source_path,
                source_pointer=args.pointer,
                bookmark_id=args.bookmark_id,
                tags=args.tag or [],
                note=args.note,
            )
        except (FileNotFoundError, CaseBookmarkError) as exc:
            parser.error(str(exc))
        save_case_payload(case_path, payload)
        audit_output = audit_path_for(case_path)
        write_audit_record(
            audit_output,
            command="case",
            options={
                "case_id": args.case_id,
                "title": args.title,
                "source": str(source_path) if source_path else None,
                "pointer": args.pointer,
                "bookmark_id": args.bookmark_id,
                "tags": args.tag or [],
            },
            input_files=[("source-json", source_path)] if source_path else [],
            output_files=[("case-json", case_path)],
        )
        print(f"Saved case JSON: {case_path}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Bookmarks: {payload['summary']['bookmark_count']}")
        return 0

    if args.command == "timeline":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        report_output = (
            Path(args.report).expanduser().resolve()
            if args.report
            else output.with_name(f"{output.stem}-report.md")
        )
        try:
            payload = run_timeline(
                root=root,
                input_kind=args.input_kind,
                files_inputs=[Path(value) for value in (args.files or [])],
                docs_inputs=[Path(value) for value in (args.docs or [])],
                artifacts_inputs=[Path(value) for value in (args.artifacts or [])],
                rule_set=rule_set,
            )
        except TimelineError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        report_output.parent.mkdir(parents=True, exist_ok=True)
        report_output.write_text(build_timeline_report(payload), encoding="utf-8")
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="timeline",
            options={
                "files": args.files or [],
                "docs": args.docs or [],
                "artifacts": args.artifacts or [],
                "input_kind": args.input_kind,
                "rules": str(rule_set.path) if rule_set else None,
                "output": str(output),
                "report": str(report_output),
            },
            input_root=resolve_input_root(root, kind=args.input_kind),
            input_files=[
                *[(f"files:{index}", Path(path)) for index, path in enumerate(args.files or [], start=1)],
                *[(f"docs:{index}", Path(path)) for index, path in enumerate(args.docs or [], start=1)],
                *[(f"artifacts:{index}", Path(path)) for index, path in enumerate(args.artifacts or [], start=1)],
            ],
            output_files=[("timeline-json", output), ("timeline-report", report_output)],
        )
        print(f"Saved timeline JSON: {output}")
        print(f"Saved timeline report: {report_output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Events: {payload['summary']['event_count']}")
        return 0

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
                dry_run=args.dry_run,
                read_only=args.read_only,
                max_extract_size_bytes=args.max_extract_size_bytes,
                max_file_count=args.max_file_count,
                overwrite=args.overwrite,
            )
        except ExtractError as exc:
            parser.error(str(exc))
        write_result(payload, manifest_output)
        audit_output = audit_path_for(manifest_output)
        write_audit_record(
            audit_output,
            command="extract",
            options={
                "manifest": str(manifest_output),
                "output_dir": str(output_dir),
                "name_contains": args.name_contains or [],
                "path_contains": args.path_contains or [],
                "extensions": args.ext or [],
                "categories": args.category or [],
                "kinds": args.kind or [],
                "limit": args.limit,
                "dry_run": args.dry_run,
                "read_only": args.read_only,
                "max_extract_size_bytes": args.max_extract_size_bytes,
                "max_file_count": args.max_file_count,
                "overwrite": args.overwrite,
            },
            input_root=Path(payload["root"]).resolve() if payload.get("root") else None,
            input_files=[("input-json", input_json)],
            output_files=[("extract-manifest", manifest_output)]
            + [
                (f"extracted:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in payload.get("entries", [])
            ],
        )
        print(f"Saved extract manifest JSON: {manifest_output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Selected: {payload['summary']['selected_count']}  Extracted: {payload['summary']['extracted_count']}")
        return 0

    root = Path(args.root).expanduser().resolve()
    input_root = resolve_input_root(root, kind=getattr(args, "input_kind", None))
    if args.command == "run":
        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else root / f"rapidtriage-run-{args.mode.lower()}"
        )
        try:
            payload = run_triage_mode(
                root,
                mode=args.mode,
                output_dir=output_dir,
                input_kind=args.input_kind,
                dry_run=args.dry_run,
                read_only=args.read_only,
                max_extract_size_bytes=args.max_extract_size_bytes,
                max_file_count=args.max_file_count,
                overwrite=args.overwrite,
                rule_set=rule_set,
            )
        except RunModeError as exc:
            parser.error(str(exc))
        print(f"Saved run summary JSON: {payload['outputs']['summary']}")
        print(f"Saved run report: {payload['outputs']['report']}")
        if payload.get("audit"):
            print(f"Saved audit JSON: {payload['audit']}")
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
            payload = run_artifact_collection(root, kind=args.kind, input_kind=args.input_kind, rule_set=rule_set)
        except ArtifactCollectionError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="artifacts",
            options={"kind": args.kind, "output": str(output), "input_kind": args.input_kind, "rules": args.rules},
            input_root=input_root,
            output_files=[("artifacts-json", output)],
        )
        print(f"Saved artifact collector JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Kind: {payload['kind']}  Artifacts: {payload['summary']['artifact_count']}")
        return 0

    output = Path(args.output).expanduser().resolve()

    if args.command == "docs":
        payload = run_docs_search(root, args.keyword, limit=args.limit, input_kind=args.input_kind, rule_set=rule_set)
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="docs",
            options={
                "keywords": args.keyword,
                "limit": args.limit,
                "output": str(output),
                "input_kind": args.input_kind,
                "rules": args.rules,
            },
            input_root=input_root,
            output_files=[("docs-json", output)],
        )
        print(f"Saved docs search JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Candidates: {payload['summary']['candidate_count']}  Matches: {payload['summary']['match_count']}")
        return 0

    if args.command == "manifest":
        payload = build_manifest(root, [], input_kind=args.input_kind)
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="manifest",
            options={"keywords": [], "output": str(output), "input_kind": args.input_kind},
            input_root=input_root,
            output_files=[("manifest-json", output)],
        )
        print(f"Saved manifest JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
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
                rule_set=rule_set,
            )
        except FileScanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="files",
            options={
                "categories": args.category or [],
                "name_contains": args.name_contains or [],
                "path_contains": args.path_contains or [],
                "extensions": args.ext or [],
                "modified_after": args.modified_after,
                "modified_before": args.modified_before,
                "limit": args.limit,
                "output": str(output),
                "input_kind": args.input_kind,
                "rules": args.rules,
            },
            input_root=input_root,
            output_files=[("files-json", output)],
        )
        print(f"Saved file scan JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Scanned: {payload['summary']['scanned_file_count']}  Candidates: {payload['summary']['candidate_count']}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
