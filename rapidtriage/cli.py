from __future__ import annotations

import argparse
import json
import textwrap
from pathlib import Path

from .core.audit import audit_path_for, write_audit_record
from .core.artifacts import ArtifactCollectionError, SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .core.benchmark import BenchmarkError, DEFAULT_BENCHMARK_FILE_COUNT, DEFAULT_BENCHMARK_KEYWORD, run_benchmark
from .core.bundle import BundleError, build_submission_bundle
from .core.case import (
    REVIEW_STATUSES,
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from .core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from .core.case_db import CaseDatabaseError, open_case_database
from .core.collect_plan import (
    DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT,
    DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES,
    CollectPlanError,
    build_collect_plan,
    run_collect_export,
    supported_collect_profiles,
)
from .core.docs import build_manifest, run_docs_search, write_result
from .core.doctor import format_doctor_text, run_doctor
from .core.evidence import identify_evidence
from .core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, SUPPORTED_DOC_KINDS, run_extract
from .core.files import ALL_FILE_CATEGORIES, FileScanError, run_files_scan
from .core.input_root import SUPPORTED_INPUT_ROOT_KINDS, resolve_input_root
from .core.normalize import NormalizationError, build_normalized_case
from .core.plugins import PluginError, load_plugin_registry, validate_plugin_manifest, read_plugin_manifest
from .core.rules import RuleConfigError, load_rule_set
from .core.run import RunModeError, SUPPORTED_RUN_MODES, run_triage_mode
from .core.sample_case import DEFAULT_SAMPLE_DIR, DEFAULT_SAMPLE_MODE, SampleCaseError, create_sample_case, run_sample_workflow
from .core.search import SearchError, run_unified_search
from .core.timeline import TimelineError, build_timeline_report, run_timeline
from .core.timeline_export import TimelineExportError, build_unified_timeline_export
from .core.validation import ValidationError, build_validation_package
from .core.vsc import VscCompareError, compare_vsc_snapshots

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
  rapidtriage docs /cases/image-mount -k password --index-output docs-index.json
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


def add_web_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="Host interface for the local web server")
    parser.add_argument("--port", type=int, default=8765, help="Port for the local web server")
    parser.add_argument("--auth-token", help="Require X-RapidTriage-Token for API calls")
    parser.add_argument("--allow-remote-without-auth", action="store_true", help="Allow non-localhost binding without auth token")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn reload for UI/API development")


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
              rapidtriage docs . -k incident --index-output rapidtriage-docs-index.json
              rapidtriage files . --output rapidtriage-files.json
              rapidtriage collect-plan /Volumes/case-mount --profile intrusion --output rapidtriage-collect-plan.json
              rapidtriage collect-export /Volumes/case-mount ./collect-export --profile intrusion --copy
              rapidtriage vsc-compare ./current ./vss/snapshot-1 --output vsc-delta.json
              rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
              rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
              rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
              rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage timeline . --output rapidtriage-timeline.json --report rapidtriage-timeline-report.md
              rapidtriage case ./incident-case.json --source rapidtriage-timeline.json --pointer /events/0 --tag suspicious
              rapidtriage manifest /Volumes/case-mount --input-kind mounted-image
              rapidtriage run . --mode fraud --output-dir ./rapidtriage-run --read-only
              rapidtriage run ./case.E01 --mode fraud --output-dir ./rapidtriage-run-e01
              rapidtriage search ./rapidtriage-run-fraud -k invoice -k password
              rapidtriage sample --run --overwrite
              rapidtriage case-db ./rapidtriage-case.db --create-case CASE-001 --name "Case 001"
              rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password
              rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant --verification-status source_opened
              rapidtriage evidence ./case.E01
              rapidtriage benchmark --output-dir ./rapidtriage-benchmark --file-count 1000
              rapidtriage validation --output-dir ./rapidtriage-validation --overwrite
              rapidtriage case-catalog --add-run ./rapidtriage-run --case-id CASE-001 --list
              rapidtriage timeline-export ./rapidtriage-run --source artifacts --output timeline-export.json
              rapidtriage normalize ./rapidtriage-run --output normalized-case.json
              rapidtriage bundle ./rapidtriage-case.json --allowed-root /cases/mount --output-dir ./submission-bundle
              rapidtriage plugins --list
              rapidtriage doctor --json
              rapidtriage web --host 127.0.0.1 --port 8765
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
              rapidtriage docs /cases/image-mount -k password --index-output docs-index.json
            """
        ),
    )
    docs.add_argument("root", help="Directory to scan")
    docs.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    docs.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    docs.add_argument("--output", default="rapidtriage-docs.json", help="JSON output path")
    docs.add_argument("--index-output", help="Optional processed-text inverted index JSON sidecar")
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

    collect_plan = sub.add_parser(
        "collect-plan",
        help="Preview KAPE-style evidence collection targets before scanning or copying",
        description="Preview KAPE-style evidence collection targets before scanning or copying",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage collect-plan /cases/image-mount --profile intrusion
              rapidtriage collect-plan /cases/image-mount --profile windows-core --output collect-plan.json --json
              rapidtriage collect-plan /cases/mac-export --profile macos-core
            """
        ),
    )
    collect_plan.add_argument("root", help="Mounted/exported evidence folder to inspect")
    collect_plan.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    collect_plan.add_argument("--profile", choices=sorted(supported_collect_profiles()), default="full", help="Target profile to preview")
    collect_plan.add_argument("--output", default="rapidtriage-collect-plan.json", help="JSON output path")
    collect_plan.add_argument("--json", action="store_true", help="Print the full JSON plan after saving it")

    collect_export = sub.add_parser(
        "collect-export",
        help="Export files selected by collect-plan profiles with hashes and copy logs",
        description="Export files selected by collect-plan profiles with hashes and copy logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage collect-export /cases/image-mount ./export --profile intrusion
              rapidtriage collect-export /cases/image-mount ./export --profile windows-core --copy
              rapidtriage collect-export /cases/image-mount ./export --profile full --copy --max-file-count 0 --max-total-bytes 0
            """
        ),
    )
    collect_export.add_argument("root", help="Mounted/exported evidence folder to inspect")
    collect_export.add_argument("output_dir", help="Directory that receives the export manifest and optional copied evidence")
    collect_export.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    collect_export.add_argument("--profile", choices=sorted(supported_collect_profiles()), default="intrusion", help="Target profile to export")
    collect_export.add_argument("--copy", action="store_true", help="Actually copy selected files; omitted means dry-run manifest only")
    collect_export.add_argument("--overwrite", action="store_true", help="Allow overwriting existing files in OUTPUT_DIR/evidence")
    collect_export.add_argument(
        "--max-file-count",
        type=int,
        default=DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT,
        help="Maximum selected files to copy or include (0 means unlimited)",
    )
    collect_export.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES,
        help="Maximum copied source bytes (0 means unlimited)",
    )
    collect_export.add_argument(
        "--manifest",
        help="Manifest JSON output path (default: OUTPUT_DIR/rapidtriage-collect-export.json)",
    )
    collect_export.add_argument("--json", action="store_true", help="Print the full JSON export manifest after saving it")

    vsc_compare = sub.add_parser(
        "vsc-compare",
        help="Compare current files against one or more Volume Shadow Copy snapshot folders",
        description="Compare current files against one or more Volume Shadow Copy snapshot folders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage vsc-compare ./current ./snapshot-1 --output vsc-delta.json
              rapidtriage vsc-compare ./current ./snapshot-1 ./snapshot-2 --hash --max-records 5000
            """
        ),
    )
    vsc_compare.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_compare.add_argument("snapshot_roots", nargs="+", help="One or more VSC snapshot file trees to compare")
    vsc_compare.add_argument("--output", default="rapidtriage-vsc-compare.json", help="JSON output path")
    vsc_compare.add_argument("--hash", action="store_true", help="Hash common files before deciding modified status")
    vsc_compare.add_argument("--case-sensitive", action="store_true", help="Compare paths case-sensitively")
    vsc_compare.add_argument("--max-records", type=int, default=10000, help="Maximum change records per snapshot (0 means unlimited)")
    vsc_compare.add_argument("--json", action="store_true", help="Print the full JSON comparison after saving it")

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

    search = sub.add_parser(
        "search",
        help="Search a completed run across documents, files, artifacts, timeline, and OCR text",
        description="Search a completed run across documents, files, artifacts, timeline, and OCR text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage search ./rapidtriage-run-fraud -k invoice -k password
              rapidtriage search ./rapidtriage-run-fraud/rapidtriage-run-summary.json -k malicious --no-ocr
            """
        ),
    )
    search.add_argument("run_output", help="Run output directory or rapidtriage-run-summary.json")
    search.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    search.add_argument("--output", default="rapidtriage-search.json", help="JSON output path")
    search.add_argument("--limit", type=int, default=500, help="Maximum number of combined matches")
    search.add_argument("--no-ocr", action="store_true", help="Skip OCR over image candidates")

    doctor = sub.add_parser(
        "doctor",
        help="Check local runtime, optional tools, storage, and web UI assets",
        description="Check local runtime, optional tools, storage, and web UI assets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage doctor
              rapidtriage doctor --json
              rapidtriage doctor --host 127.0.0.1 --port 8765 --strict
            """
        ),
    )
    doctor.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    doctor.add_argument("--host", default="127.0.0.1", help="Host to check for web port availability")
    doctor.add_argument("--port", type=int, default=8765, help="Port to check for web server availability")
    doctor.add_argument("--app-data-dir", help="Override the app data directory to probe")
    doctor.add_argument("--no-write-probe", action="store_true", help="Do not create a temporary write probe file")
    doctor.add_argument("--strict", action="store_true", help="Return exit code 1 when any doctor check is error")

    sample = sub.add_parser(
        "sample",
        help="Create a synthetic sample evidence folder and optionally run triage",
        description="Create a synthetic sample evidence folder and optionally run triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage sample
              rapidtriage sample --output-dir ./rapidtriage-sample --run
              rapidtriage sample --run --mode fraud --overwrite --json
            """
        ),
    )
    sample.add_argument("--output-dir", default=DEFAULT_SAMPLE_DIR, help=f"Sample output directory (default: {DEFAULT_SAMPLE_DIR})")
    sample.add_argument("--run", action="store_true", help="Run the sample evidence through rapidtriage after creating it")
    sample.add_argument("--mode", choices=sorted(SUPPORTED_RUN_MODES), default=DEFAULT_SAMPLE_MODE, help=f"Run mode for --run (default: {DEFAULT_SAMPLE_MODE})")
    sample.add_argument("--overwrite", action="store_true", help="Delete and recreate the sample output directory if it already has files")
    sample.add_argument("--read-only", action="store_true", help="Use read-only extract mode when --run is enabled")
    sample.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_db = sub.add_parser(
        "case-db",
        help="Initialize or inspect the experimental SQLite case database",
        description="Initialize or inspect the experimental SQLite case database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-db ./rapidtriage-case.db
              rapidtriage case-db ./rapidtriage-case.db --create-case CASE-001 --name "Case 001"
              rapidtriage case-db ./rapidtriage-case.db --import-run ./rapidtriage-sample/run-output --case-id CASE-001
              rapidtriage case-db ./rapidtriage-case.db --list --json
            """
        ),
    )
    case_db.add_argument("database", help="Path to the SQLite case database")
    case_db.add_argument("--create-case", metavar="CASE_ID", help="Create a case record after initializing the DB")
    case_db.add_argument("--import-run", help="Import a completed run output directory or rapidtriage-run-summary.json")
    case_db.add_argument("--case-id", help="Case ID for --import-run")
    case_db.add_argument("--name", help="Case display name for --create-case")
    case_db.add_argument("--description", default="", help="Case description for --create-case")
    case_db.add_argument("--examiner", default="", help="Examiner name for --create-case")
    case_db.add_argument("--organization", default="", help="Organization name for --create-case")
    case_db.add_argument("--case-root", help="Evidence/case root path for --create-case")
    case_db.add_argument("--list", action="store_true", help="List cases after initialization")
    case_db.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_search = sub.add_parser(
        "case-search",
        help="Search an imported SQLite case database",
        description="Search an imported SQLite case database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password
              rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k powershell -k download --limit 25 --json
            """
        ),
    )
    case_search.add_argument("database", help="Path to the SQLite case database")
    case_search.add_argument("--case-id", required=True, help="Case ID to search")
    case_search.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    case_search.add_argument("--limit", type=int, default=100, help="Maximum number of combined matches")
    case_search.add_argument("--source", action="append", help="Limit to a result source such as documents, files, artifacts, or timeline")
    case_search.add_argument("--review-status", help="Limit by analyst review status")
    case_search.add_argument("--verification-status", help="Limit by review verification status")
    case_search.add_argument("--save-as", help="Save this keyword/filter set for reuse")
    case_search.add_argument("--output", help="Optional JSON output path")
    case_search.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_review = sub.add_parser(
        "case-review",
        help="Mark review and verification state for a Case DB search result",
        description="Mark review and verification state for a Case DB search result",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant
              rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type artifact --target-id 3 --verification-status source_opened --include-in-report
            """
        ),
    )
    case_review.add_argument("database", help="Path to the SQLite case database")
    case_review.add_argument("--case-id", required=True, help="Case ID to update")
    case_review.add_argument("--target-type", required=True, help="Target type from case-search result")
    case_review.add_argument("--target-id", required=True, help="Target id from case-search result")
    case_review.add_argument("--status", default="unreviewed", help="Review status such as relevant, notable, excluded, or follow_up")
    case_review.add_argument("--verification-status", default="unverified", help="Verification status such as source_opened, cross_checked, verified, or rejected")
    case_review.add_argument("--tag", action="append", help="Review tag (repeatable)")
    case_review.add_argument("--note", default="", help="Review note")
    case_review.add_argument("--reviewer", default="", help="Reviewer name")
    case_review.add_argument("--include-in-report", action="store_true", help="Mark target as report candidate")
    case_review.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    evidence = sub.add_parser(
        "evidence",
        help="Identify the evidence adapter that would handle a source path",
        description="Identify the evidence adapter that would handle a source path",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage evidence ./mounted-folder
              rapidtriage evidence ./case.E01 --json
            """
        ),
    )
    evidence.add_argument("source", help="Evidence source path to identify")
    evidence.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    benchmark = sub.add_parser(
        "benchmark",
        help="Run a synthetic or existing-root performance benchmark",
        description="Run a synthetic or existing-root performance benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage benchmark --output-dir ./rapidtriage-benchmark
              rapidtriage benchmark --root /cases/mounted --output-dir ./bench-mounted --keyword password
            """
        ),
    )
    benchmark.add_argument("--root", help="Optional existing evidence root. If omitted, a synthetic case is generated.")
    benchmark.add_argument("--output-dir", required=True, help="Directory for benchmark outputs")
    benchmark.add_argument("--file-count", type=int, default=DEFAULT_BENCHMARK_FILE_COUNT, help="Synthetic file count")
    benchmark.add_argument("--keyword", default=DEFAULT_BENCHMARK_KEYWORD, help="Keyword to seed/search")
    benchmark.add_argument("--mode", choices=sorted(SUPPORTED_RUN_MODES), default="fraud", help="Run mode")
    benchmark.add_argument("--search-iterations", type=int, default=3, help="Repeated search samples for p50/p95")
    benchmark.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty benchmark output directory")
    benchmark.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    validation = sub.add_parser(
        "validation",
        help="Build a release validation package",
        description="Build a release validation package with required checks, commands, documents, and known limits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage validation --output-dir ./rapidtriage-validation
              rapidtriage validation --output-dir ./rapidtriage-validation --overwrite --json
            """
        ),
    )
    validation.add_argument("--output-dir", required=True, help="Directory for validation JSON and Markdown outputs")
    validation.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty validation output directory")
    validation.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_catalog = sub.add_parser(
        "case-catalog",
        help="Manage the local case catalog for user-facing case lists",
        description="Manage the local case catalog for user-facing case lists",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-catalog --list
              rapidtriage case-catalog --add-run ./rapidtriage-run --case-id CASE-001 --name "Case 001" --list
              rapidtriage case-catalog --export CASE-001 --archive ./CASE-001.zip
            """
        ),
    )
    case_catalog.add_argument("--catalog", default=str(default_case_catalog_path()), help="Catalog JSON path")
    case_catalog.add_argument("--add-run", help="Add a completed run output directory or summary JSON to a case")
    case_catalog.add_argument("--case-id", help="Case ID for --add-run or --export")
    case_catalog.add_argument("--name", help="Case display name")
    case_catalog.add_argument("--description", default="", help="Case description")
    case_catalog.add_argument("--examiner", default="", help="Examiner name")
    case_catalog.add_argument("--organization", default="", help="Organization name")
    case_catalog.add_argument("--list", action="store_true", help="List catalog cases")
    case_catalog.add_argument("--export", metavar="CASE_ID", help="Export a catalog case entry to a zip archive")
    case_catalog.add_argument("--archive", help="Archive path for --export or --import")
    case_catalog.add_argument("--import", dest="import_archive", help="Import a case catalog archive")
    case_catalog.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    timeline_export = sub.add_parser(
        "timeline-export",
        help="Export an AXIOM-style normalized timeline from a completed run",
        description="Export an AXIOM-style normalized timeline from a completed run",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    timeline_export.add_argument("run_output", help="Completed run output directory or summary JSON")
    timeline_export.add_argument("--start", help="Keep events at or after this ISO timestamp")
    timeline_export.add_argument("--end", help="Keep events at or before this ISO timestamp")
    timeline_export.add_argument("--source", help="Filter by event source")
    timeline_export.add_argument("--event-type", help="Filter by event type")
    timeline_export.add_argument("--reviewed-status", help="Filter by review status")
    timeline_export.add_argument("--limit", type=int, default=0, help="Maximum events to include")
    timeline_export.add_argument("--output", default="rapidtriage-timeline-export.json", help="JSON output path")
    timeline_export.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    normalize = sub.add_parser(
        "normalize",
        help="Normalize completed run outputs into stable forensic model collections",
        description="Normalize completed run outputs into stable forensic model collections",
    )
    normalize.add_argument("run_output", help="Completed run output directory or summary JSON")
    normalize.add_argument("--case-id", help="Case ID to write into the normalized model")
    normalize.add_argument("--output", default="rapidtriage-normalized-case.json", help="JSON output path")
    normalize.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    bundle = sub.add_parser(
        "bundle",
        help="Build a submission bundle with report, selected evidence list, hashes, and audit",
        description="Build a submission bundle with report, selected evidence list, hashes, and audit",
    )
    bundle.add_argument("case_json", help="rapidtriage case JSON")
    bundle.add_argument("--allowed-root", action="append", required=True, help="Allowed evidence root for hashing/copy checks")
    bundle.add_argument("--output-dir", required=True, help="Bundle output directory")
    bundle.add_argument("--include-all", action="store_true", help="Hash all bookmarks instead of only report candidates")
    bundle.add_argument("--max-items", type=int, default=500, help="Maximum evidence rows to include")
    bundle.add_argument("--title", help="Report title")
    bundle.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    plugins = sub.add_parser(
        "plugins",
        help="List or validate RapidTriage plugin manifests",
        description="List or validate RapidTriage plugin manifests",
    )
    plugins.add_argument("--plugin-dir", action="append", help="Directory containing plugin.json files")
    plugins.add_argument("--validate", help="Validate one plugin.json manifest")
    plugins.add_argument("--list", action="store_true", help="List built-in and discovered plugins")
    plugins.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    case_parser.add_argument("--review-status", choices=REVIEW_STATUSES, help="Analyst review decision for the bookmark")
    case_parser.add_argument("--include-in-report", action="store_true", help="Mark the bookmark as a report candidate")
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
              rapidtriage run /cases/image.E01 --mode fraud --output-dir ./rapidtriage-run-e01
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

    web = sub.add_parser(
        "web",
        help="Start the local rapidtriage web UI and API server",
        description="Start the local rapidtriage web UI and API server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage web
              rapidtriage web --host 127.0.0.1 --port 8765
            """
        ),
    )
    add_web_arguments(web)
    return parser


def build_web_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapidtriage-web",
        description="Start the local rapidtriage web UI and API server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage-web
              rapidtriage-web --host 127.0.0.1 --port 8765
            """
        ),
    )
    add_web_arguments(parser)
    return parser


def run_web_server(host: str, port: int, reload: bool = False, auth_token: str | None = None, allow_remote_without_auth: bool = False) -> int:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("rapidtriage web requires the 'web' extra: pip install 'dashcam-tools[web]'") from exc
    if host not in {"127.0.0.1", "localhost", "::1"} and not auth_token and not allow_remote_without_auth:
        raise RuntimeError(
            "Refusing to bind RapidTriage to a non-localhost interface without --auth-token. "
            "Use --auth-token or --allow-remote-without-auth if you understand the risk."
        )
    print(f"Starting rapidtriage web UI at http://{host}:{port}")
    if auth_token:
        import os

        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
    uvicorn.run("rapidtriage.api.app:app", host=host, port=port, reload=reload)
    return 0


def web_main(argv=None) -> int:
    parser = build_web_parser()
    args = parser.parse_args(argv)
    try:
        return run_web_server(args.host, args.port, args.reload, args.auth_token, args.allow_remote_without_auth)
    except RuntimeError as exc:
        parser.error(str(exc))
    return 2


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
                review_status=args.review_status,
                include_in_report=args.include_in_report if args.include_in_report else None,
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
                "review_status": args.review_status,
                "include_in_report": args.include_in_report,
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

    if args.command == "web":
        try:
            return run_web_server(args.host, args.port, args.reload, args.auth_token, args.allow_remote_without_auth)
        except RuntimeError as exc:
            parser.error(str(exc))

    if args.command == "doctor":
        payload = run_doctor(
            host=args.host,
            port=args.port,
            app_data_dir=Path(args.app_data_dir).expanduser().resolve() if args.app_data_dir else None,
            write_probe=not args.no_write_probe,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(format_doctor_text(payload))
        return 1 if args.strict and payload["status"] == "error" else 0

    if args.command == "sample":
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = (
                run_sample_workflow(output_dir, mode=args.mode, overwrite=args.overwrite, read_only=args.read_only)
                if args.run
                else create_sample_case(output_dir, overwrite=args.overwrite)
            )
        except (SampleCaseError, RunModeError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Created sample evidence: {payload['evidence_root']}")
            print(f"Saved expected output guide: {payload['expected']}")
            if payload.get("run"):
                run_payload = payload["run"]
                print(f"Saved sample run summary JSON: {run_payload['summary']}")
                print(f"Saved sample run report: {run_payload['report']}")
        return 0

    if args.command == "case-db":
        database_path = Path(args.database).expanduser().resolve()
        try:
            database = open_case_database(database_path)
            init_payload = database.initialize()
            created_case = None
            imported_run = None
            if args.create_case:
                created_case = database.create_case(
                    case_id=args.create_case,
                    name=args.name,
                    description=args.description,
                    examiner=args.examiner,
                    organization=args.organization,
                    case_root=Path(args.case_root).expanduser().resolve() if args.case_root else None,
                )
                database.add_audit_event(
                    case_id=created_case.case_id,
                    action="case.created",
                    target_type="case",
                    target_id=created_case.case_id,
                    params_json=json.dumps({"command": "case-db"}, ensure_ascii=False),
                )
            if args.import_run:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-run")
                imported_run = database.import_run_output(
                    Path(args.import_run).expanduser().resolve(),
                    case_id=import_case_id,
                    case_name=args.name,
                )
            cases = database.list_cases() if args.list or created_case is not None else []
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        payload = {
            "command": "case-db",
            "database": str(database_path),
            "schema_version": init_payload["schema_version"],
            "tables": init_payload["tables"],
            "created_case": created_case.to_dict() if created_case else None,
            "imported_run": imported_run,
            "cases": [case.to_dict() for case in cases],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Initialized case DB: {database_path}")
            print(f"Schema version: {payload['schema_version']}")
            if created_case:
                print(f"Created case: {created_case.case_id}")
            if imported_run:
                print(f"Imported run into case: {imported_run['case_id']}")
                print(f"Import counts: {imported_run['summary']}")
            if cases:
                print(f"Cases: {len(cases)}")
                for case in cases:
                    print(f"- {case.case_id}: {case.name}")
        return 0

    if args.command == "case-search":
        database_path = Path(args.database).expanduser().resolve()
        try:
            database = open_case_database(database_path)
            payload = database.search_case(
                case_id=args.case_id,
                keywords=args.keyword,
                limit=args.limit,
                sources=args.source,
                review_status=args.review_status,
                verification_status=args.verification_status,
            )
            if args.save_as:
                payload["saved_search"] = database.save_search(
                    case_id=args.case_id,
                    name=args.save_as,
                    keywords=args.keyword,
                    limit=args.limit,
                    sources=args.source,
                    review_status=args.review_status,
                    verification_status=args.verification_status,
                    created_by="cli",
                )
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json or args.output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Case search matches: {payload['summary']['match_count']}")
            for match in payload["matches"]:
                print(
                    f"- {match['citation_id']} [{match['source']}] "
                    f"{match.get('title') or match.get('path')}: {match.get('preview') or ''}"
                )
        return 0

    if args.command == "case-review":
        try:
            database = open_case_database(Path(args.database).expanduser().resolve())
            payload = database.mark_review(
                case_id=args.case_id,
                target_type=args.target_type,
                target_id=args.target_id,
                status=args.status,
                verification_status=args.verification_status,
                tags=args.tag or [],
                note=args.note,
                reviewer=args.reviewer,
                include_in_report=args.include_in_report,
            )
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved review mark: {payload['citation_id']}")
            print(f"Target: {payload['target_type']}:{payload['target_id']}")
            print(f"Status: {payload['status']} / {payload['verification_status']}")
        return 0

    if args.command == "evidence":
        payload = identify_evidence(Path(args.source)).to_dict()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Adapter: {payload['adapter']}")
            print(f"Format: {payload['detected_format']}")
            print(f"Supported now: {payload['supported']}")
            print(f"Message: {payload['message']}")
            if payload["missing_tools"]:
                print(f"Missing tools: {', '.join(payload['missing_tools'])}")
        return 0

    if args.command == "benchmark":
        try:
            payload = run_benchmark(
                root=Path(args.root).expanduser().resolve() if args.root else None,
                output_dir=Path(args.output_dir).expanduser().resolve(),
                file_count=args.file_count,
                keyword=args.keyword,
                mode=args.mode,
                search_iterations=args.search_iterations,
                overwrite=args.overwrite,
            )
        except (BenchmarkError, SearchError, RunModeError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            metrics = payload["metrics"]
            print(f"Saved benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved benchmark report: {payload['outputs']['markdown']}")
            print(
                "Ingest: "
                f"{metrics['ingest_seconds']}s  Search p50: {metrics['search_p50_seconds']}s  "
                f"Search p95: {metrics['search_p95_seconds']}s"
            )
        return 0

    if args.command == "validation":
        try:
            payload = build_validation_package(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (ValidationError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved validation JSON: {payload['outputs']['json']}")
            print(f"Saved validation report: {payload['outputs']['markdown']}")
            print(f"Score target: {payload['score_target']}/100")
        return 0

    if args.command == "case-catalog":
        catalog = CaseCatalog(Path(args.catalog).expanduser().resolve())
        added_case = None
        exported = None
        imported = None
        try:
            if args.add_run:
                if not args.case_id:
                    parser.error("--case-id is required with --add-run")
                added_case = catalog.add_run(
                    run_output=Path(args.add_run).expanduser().resolve(),
                    case_id=args.case_id,
                    name=args.name,
                    description=args.description,
                    examiner=args.examiner,
                    organization=args.organization,
                )
            if args.export:
                archive = Path(args.archive).expanduser().resolve() if args.archive else Path(f"{args.export}.zip").resolve()
                exported = catalog.export_case(case_id=args.export, output_zip=archive)
            if args.import_archive:
                imported = catalog.import_archive(Path(args.import_archive).expanduser().resolve())
            cases = catalog.list_cases() if args.list or not any([added_case, exported, imported]) else []
        except CaseCatalogError as exc:
            parser.error(str(exc))
        payload = {
            "command": "case-catalog",
            "catalog": str(catalog.path),
            "added_case": added_case,
            "exported": exported,
            "imported": imported,
            "cases": cases,
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            if added_case:
                print(f"Added case: {added_case['case_id']}")
            if exported:
                print(f"Exported case archive: {exported['archive']}")
            if imported:
                print(f"Imported case: {imported['case_id']}")
            if cases:
                print(f"Cases: {len(cases)}")
                for case in cases:
                    print(f"- {case.get('case_id')}: {case.get('name')} ({len(case.get('runs', []))} runs)")
        return 0

    if args.command == "timeline-export":
        try:
            payload = build_unified_timeline_export(
                Path(args.run_output).expanduser().resolve(),
                start=args.start,
                end=args.end,
                source=args.source,
                event_type=args.event_type,
                reviewed_status=args.reviewed_status,
                limit=args.limit,
            )
        except (TimelineExportError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        output = Path(args.output).expanduser().resolve()
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved timeline export JSON: {output}")
            print(f"Events: {payload['summary']['event_count']}")
        return 0

    if args.command == "normalize":
        try:
            payload = build_normalized_case(Path(args.run_output).expanduser().resolve(), case_id=args.case_id)
        except (NormalizationError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        output = Path(args.output).expanduser().resolve()
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved normalized case JSON: {output}")
            print(f"Models: {payload['summary']}")
        return 0

    if args.command == "bundle":
        try:
            payload = build_submission_bundle(
                case_json=Path(args.case_json).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                allowed_roots=[Path(path).expanduser().resolve() for path in args.allowed_root],
                include_all=args.include_all,
                max_items=args.max_items,
                title=args.title,
            )
        except (BundleError, CaseBookmarkError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved bundle manifest: {payload['outputs']['manifest']}")
            print(f"Saved bundle archive: {payload['outputs']['archive']}")
            print(f"Archive SHA256: {payload['archive_hashes']['sha256']}")
        return 0

    if args.command == "plugins":
        try:
            if args.validate:
                plugin = validate_plugin_manifest(
                    read_plugin_manifest(Path(args.validate).expanduser().resolve()),
                    manifest_path=Path(args.validate).expanduser().resolve(),
                )
                payload = {"command": "plugins", "validated": plugin, "plugins": [plugin], "errors": []}
            else:
                payload = load_plugin_registry([Path(path) for path in (args.plugin_dir or [])])
        except PluginError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            for plugin in payload.get("plugins", []):
                print(f"- {plugin['id']} [{plugin['kind']}] {plugin['version']} enabled={plugin['enabled']}")
            for error in payload.get("errors", []):
                print(f"! {error['path']}: {error['error']}")
        return 0

    if args.command == "search":
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_unified_search(run_output, args.keyword, include_ocr=not args.no_ocr, limit=args.limit)
        except SearchError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="search",
            options={
                "keywords": args.keyword,
                "output": str(output),
                "limit": args.limit,
                "ocr": not args.no_ocr,
            },
            input_files=[("run-summary", input_summary)],
            output_files=[("search-json", output)],
        )
        print(f"Saved search JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Matches: {payload['summary']['match_count']}")
        return 0

    if args.command == "vsc-compare":
        current_root = Path(args.current_root).expanduser().resolve()
        snapshot_roots = [Path(item).expanduser().resolve() for item in args.snapshot_roots]
        output = Path(args.output).expanduser().resolve()
        try:
            payload = compare_vsc_snapshots(
                current_root,
                snapshot_roots,
                compute_hashes=args.hash,
                case_sensitive=args.case_sensitive,
                max_records=args.max_records,
            )
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-compare",
            options={
                "current_root": str(current_root),
                "snapshot_roots": [str(path) for path in snapshot_roots],
                "output": str(output),
                "hash": args.hash,
                "case_sensitive": args.case_sensitive,
                "max_records": args.max_records,
            },
            input_root=current_root,
            output_files=[("vsc-compare-json", output)],
            notes=[
                "Snapshot roots are recorded in options; input_root inventory covers the current root only.",
                "Use --hash for byte-level modified confirmation when runtime permits.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved VSC compare JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Snapshots: {summary['snapshot_count']}  "
                f"Deleted: {summary['deleted']}  Added: {summary['added']}  Modified: {summary['modified']}"
            )
        return 0

    if args.command == "collect-plan":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = build_collect_plan(root, profile=args.profile, input_kind=args.input_kind)
        except CollectPlanError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="collect-plan",
            options={
                "root": str(root),
                "profile": args.profile,
                "input_kind": args.input_kind,
                "output": str(output),
            },
            output_files=[("collect-plan-json", output)],
            notes=[
                "collect-plan intentionally does not hash or inventory the entire input root to keep large evidence planning fast.",
                "Use manifest/run when a full input-root inventory hash is required.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved collect plan JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Profile: {payload['profile']}  "
                f"Present: {summary['present_count']}  Missing: {summary['missing_count']}"
            )
            for category, counts in summary["category_counts"].items():
                print(
                    f"- {category}: {counts['present_count']}/{counts['target_count']} present "
                    f"({counts['missing_count']} missing)"
                )
        return 0

    if args.command == "collect-export":
        root = Path(args.root).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        manifest_output = (
            Path(args.manifest).expanduser().resolve()
            if args.manifest
            else output_dir / "rapidtriage-collect-export.json"
        )
        try:
            payload = run_collect_export(
                root,
                output_dir,
                profile=args.profile,
                input_kind=args.input_kind,
                copy_files=args.copy,
                max_file_count=args.max_file_count,
                max_total_bytes=args.max_total_bytes,
                overwrite=args.overwrite,
            )
        except CollectPlanError as exc:
            parser.error(str(exc))
        write_result(payload, manifest_output)
        audit_output = audit_path_for(manifest_output)
        write_audit_record(
            audit_output,
            command="collect-export",
            options={
                "root": str(root),
                "profile": args.profile,
                "input_kind": args.input_kind,
                "output_dir": str(output_dir),
                "manifest": str(manifest_output),
                "copy": args.copy,
                "max_file_count": args.max_file_count,
                "max_total_bytes": args.max_total_bytes,
                "overwrite": args.overwrite,
            },
            input_files=[
                (f"source:{index}", Path(entry["source_path"]))
                for index, entry in enumerate(payload.get("entries", []), start=1)
                if isinstance(entry, dict) and entry.get("source_path")
            ],
            output_files=[("collect-export-json", manifest_output)]
            + [
                (f"exported:{entry['relative_path']}", Path(entry["destination_path"]))
                for entry in payload.get("entries", [])
                if isinstance(entry, dict) and entry.get("copied") and entry.get("destination_path")
            ],
            notes=[
                "collect-export copies only selected profile targets and skips broad inventory-only directories by default.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved collect export JSON: {manifest_output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Evidence directory: {payload['evidence_dir']}")
            print(
                f"Selected: {summary['selected_file_count']}  "
                f"Copied: {summary['copied_file_count']}  Skipped: {summary['skipped_count']}"
            )
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
        index_output = Path(args.index_output).expanduser().resolve() if args.index_output else None
        payload = run_docs_search(
            root,
            args.keyword,
            limit=args.limit,
            input_kind=args.input_kind,
            rule_set=rule_set,
            index_output=index_output,
        )
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="docs",
            options={
                "keywords": args.keyword,
                "limit": args.limit,
                "output": str(output),
                "index_output": str(index_output) if index_output else None,
                "input_kind": args.input_kind,
                "rules": args.rules,
            },
            input_root=input_root,
            output_files=[("docs-json", output)] + ([("docs-index", index_output)] if index_output else []),
        )
        print(f"Saved docs search JSON: {output}")
        if index_output is not None:
            print(f"Saved docs index JSON: {index_output}")
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
