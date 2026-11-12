"""Parser registration for Case DB, catalog and export commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.case_catalog import default_case_catalog_path
from ...core.run import SUPPORTED_RUN_MODES
from ...core.sample_case import DEFAULT_SAMPLE_DIR, DEFAULT_SAMPLE_MODE


def register_case_db(sub: argparse._SubParsersAction) -> None:
    """Register case-backup, case-restore, case-acquisition, sample, case-db, case-search, case-review, case-db-report, case-export-uco, cross-case-correlate."""
    case_backup = sub.add_parser("case-backup", help="Back up a RapidTriage Case DB with hashes")
    case_backup.add_argument("database", help="Case DB path")
    case_backup.add_argument("--output-dir", required=True, help="Directory for backup files and manifest")
    case_backup.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty backup directory")
    case_backup.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_restore = sub.add_parser("case-restore", help="Restore a RapidTriage Case DB backup")
    case_restore.add_argument("manifest", help="Backup manifest JSON")
    case_restore.add_argument("--output", required=True, help="Restored Case DB path")
    case_restore.add_argument("--overwrite", action="store_true", help="Overwrite restored output if it exists")
    case_restore.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_acquisition = sub.add_parser(
        "case-acquisition",
        help="Record or list acquisition/write-blocker metadata for a Case DB",
        description="Record acquisition operator, source, write-blocker, time, tool, and whole-source hash metadata",
    )
    case_acquisition.add_argument("database", help="Case DB path")
    case_acquisition.add_argument("--case-id", required=True, help="Case identifier")
    case_acquisition.add_argument("--evidence-source-citation-id", default="", help="Optional evidence source citation ID")
    case_acquisition.add_argument("--operator", default="", help="Acquisition operator/examiner")
    case_acquisition.add_argument("--started-at", default="", help="Acquisition start timestamp")
    case_acquisition.add_argument("--completed-at", default="", help="Acquisition completion timestamp")
    case_acquisition.add_argument("--source-identifier", default="", help="Device/source serial, asset tag, or image identifier")
    case_acquisition.add_argument("--write-blocker", default="", help="Write-blocker model/serial/status")
    case_acquisition.add_argument("--tool", default="", help="Acquisition tool name")
    case_acquisition.add_argument("--tool-version", default="", help="Acquisition tool version")
    case_acquisition.add_argument("--whole-source-sha256", default="", help="Whole-source SHA256 from acquisition workflow")
    case_acquisition.add_argument("--notes", default="", help="Acquisition notes")
    case_acquisition.add_argument("--list", action="store_true", help="List existing acquisition metadata instead of recording")
    case_acquisition.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
              rapidtriage case-db ./rapidtriage-case.db --import-vsc-compare ./vsc-delta.json --case-id CASE-001
              rapidtriage case-db ./rapidtriage-case.db --import-worker-jsonl ./worker-artifacts.jsonl --case-id CASE-001
              rapidtriage case-db ./rapidtriage-case.db --case-id CASE-001 --search-index-health --json
              rapidtriage case-db ./rapidtriage-case.db --case-id CASE-001 --rebuild-search-indexes --json
              rapidtriage case-db ./rapidtriage-case.db --list --json
            """
        ),
    )
    case_db.add_argument("database", help="Path to the SQLite case database")
    case_db.add_argument("--create-case", metavar="CASE_ID", help="Create a case record after initializing the DB")
    case_db.add_argument("--import-run", help="Import a completed run output directory or rapidtriage-run-summary.json")
    case_db.add_argument("--import-vsc-compare", help="Import a rapidtriage vsc-compare JSON as reviewable case artifacts")
    case_db.add_argument("--import-worker-jsonl", help="Import ArtifactRecordV1 JSONL emitted by worker-parse")
    case_db.add_argument("--case-id", help="Case ID for --import-run, --import-vsc-compare, or --import-worker-jsonl")
    case_db.add_argument("--name", help="Case display name for --create-case")
    case_db.add_argument("--description", default="", help="Case description for --create-case")
    case_db.add_argument("--examiner", default="", help="Examiner name for --create-case")
    case_db.add_argument("--organization", default="", help="Organization name for --create-case")
    case_db.add_argument("--case-root", help="Evidence/case root path for --create-case")
    case_db.add_argument("--search-index-health", action="store_true", help="Report case-scoped FTS search index health")
    case_db.add_argument("--rebuild-search-indexes", action="store_true", help="Rebuild case-scoped FTS indexes for large-case search")
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
    case_search.add_argument("--cursor", default="", help="Opaque next_cursor from a previous case-search response")
    case_search.add_argument("--source", action="append", help="Limit to a result source such as documents, files, artifacts, indicators, or timeline")
    case_search.add_argument("--metadata", action="append", help="Limit artifact/timeline results by metadata KEY=VALUE, repeatable")
    case_search.add_argument("--review-status", help="Limit by analyst review status")
    case_search.add_argument("--verification-status", help="Limit by review verification status")
    case_search.add_argument("--save-as", help="Save this keyword/filter set for reuse")
    case_search.add_argument("--keyword-pack", action="append", help="Add a built-in keyword pack to this case search")
    case_search.add_argument("--keyword-pack-file", action="append", help="JSON keyword pack file containing a keywords list")
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
    case_review.add_argument("--status", help="Review status such as relevant, notable, excluded, or follow_up")
    case_review.add_argument("--verification-status", help="Verification status such as source_opened, cross_checked, verified, or rejected")
    case_review.add_argument("--tag", action="append", help="Review tag (repeatable)")
    case_review.add_argument("--note", help="Review note")
    case_review.add_argument("--source-read-json", help="Append a source-read citation package review note to --note")
    case_review.add_argument("--reviewer", help="Reviewer name attributed to the mark (default: RAPIDTRIAGE_REVIEWER env, then system user)")
    case_review.add_argument("--assignee", help="Analyst assigned to follow up this result")
    case_review.add_argument("--priority", help="Review priority: urgent, high, normal, or low")
    case_review.add_argument("--due-at", help="Optional due date/time for review follow-up")
    report_flag = case_review.add_mutually_exclusive_group()
    report_flag.add_argument("--include-in-report", dest="include_in_report", action="store_true", default=None, help="Mark target as report candidate")
    report_flag.add_argument("--exclude-from-report", dest="include_in_report", action="store_false", help="Remove target from report candidates")
    case_review.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_db_report = sub.add_parser(
        "case-db-report",
        help="Export Case DB reviewed report candidates",
        description="Export Case DB reviewed report candidates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-db-report ./rapidtriage-case.db --case-id CASE-001 --output report-candidates.json
              rapidtriage case-db-report ./rapidtriage-case.db --case-id CASE-001 --include-all --json
            """
        ),
    )
    case_db_report.add_argument("database", help="Path to the SQLite case database")
    case_db_report.add_argument("--case-id", required=True, help="Case ID to export")
    case_db_report.add_argument("--include-all", action="store_true", help="Export every reviewed item, not only report candidates")
    case_db_report.add_argument("--max-items", type=int, default=500, help="Maximum reviewed items to export")
    case_db_report.add_argument("--output", help="Optional JSON output path")
    case_db_report.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    case_export_uco = sub.add_parser(
        "case-export-uco",
        help="Export a Case DB case to CASE/UCO-shaped JSON-LD",
        description="Export a Case DB case to CASE/UCO-shaped JSON-LD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage case-export-uco ./rapidtriage-case.db --case-id CASE-001
              rapidtriage case-export-uco ./rapidtriage-case.db --case-id CASE-001 --output ./report/case-001-uco.jsonld --json
            """
        ),
    )
    case_export_uco.add_argument("database", help="Path to the SQLite case database")
    case_export_uco.add_argument("--case-id", required=True, help="Case ID to export")
    case_export_uco.add_argument("--output", help="Optional JSON-LD output path (must stay under the case database directory)")
    case_export_uco.add_argument("--max-rows", type=int, default=25000, help="Maximum rows exported per table")
    case_export_uco.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    cross_case = sub.add_parser(
        "cross-case-correlate",
        help="Correlate shared hashes, paths, and artifact identifiers across case databases",
        description="Correlate shared hashes, paths, and artifact identifiers across case databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage cross-case-correlate ./case-a.db ./case-b.db
              rapidtriage cross-case-correlate ./case-a.db ./case-b.db --case-id CASE-001 --output correlation.json --json
            """
        ),
    )
    cross_case.add_argument("databases", nargs="+", help="Paths to SQLite case databases (at least two)")
    cross_case.add_argument("--case-id", action="append", help="Limit correlation to these case IDs (repeatable)")
    cross_case.add_argument("--output", help="Optional report output path (default: next to the first database)")
    cross_case.add_argument("--max-shared", type=int, default=5000, help="Maximum shared entities per section")
    cross_case.add_argument("--json", action="store_true", help="Print machine-readable JSON")


def register_catalog(sub: argparse._SubParsersAction) -> None:
    """Register case-catalog, timeline-export, normalize, bundle."""
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
