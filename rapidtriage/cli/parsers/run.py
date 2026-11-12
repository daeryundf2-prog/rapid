"""Parser registration for the run, case, files and analysis commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.case import REVIEW_STATUSES
from ...core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, SUPPORTED_DOC_KINDS
from ...core.files import ALL_FILE_CATEGORIES
from ...core.input_root import SUPPORTED_INPUT_ROOT_KINDS
from ...core.run import SUPPORTED_RUN_MODES
from ..helpers import (
    add_eventlog_output_arguments,
    add_rules_argument,
)


def register_files(sub: argparse._SubParsersAction) -> None:
    """Register files."""
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
    files.add_argument(
        "--known-good-hash-feed",
        action="append",
        default=[],
        help="Analyst-supplied MD5/SHA1/SHA256 known-good feed (TXT/CSV/JSON; repeatable)",
    )
    files.add_argument(
        "--hide-known-good",
        action="store_true",
        help="Hide files that match the known-good hash feed while preserving a suppression manifest",
    )
    files.add_argument(
        "--known-good-max-hash-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="Maximum file size to hash for known-good checks (default: 67108864)",
    )
    add_rules_argument(files)


def register_analysis(sub: argparse._SubParsersAction) -> None:
    """Register compare, extract, timeline, search, search-index, source-read, source-search, ocr-queue, indicators."""
    compare = sub.add_parser(
        "compare",
        help="Compare two files for A/B review with hashes and optional text diff",
        description="Compare two files for analyst A/B review with hashes, field differences, and bounded text diffs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage compare ./before.txt ./after.txt --output compare.json
              rapidtriage compare ./baseline.txt ./host-a.txt ./host-b.txt --label baseline --label host-a --label host-b
              rapidtriage compare ./export-a.evtx.json ./export-b.evtx.json --left-label baseline --right-label suspect --json
              rapidtriage compare ./large-a.log ./large-b.log --no-text-diff
            """
        ),
    )
    compare.add_argument("paths", nargs="+", help="Two or more files to compare; first file is the baseline for 3+ inputs")
    compare.add_argument("--left-label", default="left", help="Human label for the left file")
    compare.add_argument("--right-label", default="right", help="Human label for the right file")
    compare.add_argument("--label", action="append", help="Label for each positional file when comparing 3+ files")
    compare.add_argument("--output", default="rapidtriage-compare.json", help="JSON output path")
    compare.add_argument("--no-hash", action="store_true", help="Skip MD5/SHA1/SHA256 hashing")
    compare.add_argument("--no-text-diff", action="store_true", help="Skip bounded text diff preview")
    compare.add_argument("--max-text-bytes", type=int, default=256 * 1024, help="Maximum per-file bytes for text diff preview")
    compare.add_argument("--diff-context", type=int, default=3, help="Unified diff context lines")
    compare.add_argument("--selection-rationale", default="", help="Analyst rationale for why these evidence items are compared")
    compare.add_argument("--review-note", action="append", help="Bounded review note for a comparison row (repeatable)")
    compare.add_argument("--json", action="store_true", help="Print JSON to stdout")

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
    search.add_argument("--no-analysis", action="store_true", help="Skip clustering/entity/graph/workbook analysis pivots")
    search.add_argument("--search-mode", choices=["exact", "fuzzy", "regex"], default="exact", help="Keyword matching mode")
    search.add_argument("--fuzzy-distance", type=int, default=1, help="Maximum edit distance for --search-mode fuzzy (0-2)")
    search.add_argument("--proximity-window", type=int, default=0, help="Annotate hits where multiple keywords occur within N word tokens")
    search.add_argument("--hide-known-good", action="store_true", help="Hide search hits inherited from known-good/NSRL file matches")
    search.add_argument("--keyword-pack", action="append", help="Add a built-in keyword pack such as credentials, execution, network, browser-ai, windows-ir")
    search.add_argument("--keyword-pack-file", action="append", help="JSON keyword pack file containing a keywords list")

    search_index = sub.add_parser(
        "search-index",
        help="Build or update the run search index (rapidtriage-search.db) used by the console search page",
        description="Build (full) or update (incremental, analysis rows only) <run output>/rapidtriage-search.db",
    )
    search_index.add_argument("run_output", help="Run output directory or rapidtriage-run-summary.json")
    search_index.add_argument("--mode", choices=["full", "incremental"], default="full", help="full rebuild or per-analysis update")
    search_index.add_argument("--analysis-id", action="append", help="Analysis id to (re)index in incremental mode (repeatable; default: all)")
    search_index.add_argument("--output", help="Index path (default: <run output>/rapidtriage-search.db)")
    search_index.add_argument("--run-id", help="Run id recorded in the index meta (default: output directory name)")
    search_index.add_argument("--json", action="store_true", help="Print the build summary as JSON")

    source_read = sub.add_parser(
        "source-read",
        help="Read a source file from a completed run with bounded preview, hashes, and forensic caveats",
        description="Read a source file from a completed run with bounded preview, hashes, and forensic caveats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage source-read ./rapidtriage-run-hacking --path Users/alice/Documents/note.txt
              rapidtriage source-read ./rapidtriage-run-hacking --path /cases/mounted/Users/alice/AppData/Local/History --hash --json
            """
        ),
    )
    source_read.add_argument("run_output", help="Run output directory or rapidtriage-run-summary.json")
    source_read.add_argument("--path", required=True, help="Source file path, absolute or relative to the run analysis root")
    source_read.add_argument("--output", default="rapidtriage-source-read.json", help="JSON output path")
    source_read.add_argument("--max-chars", type=int, default=20_000, help="Maximum text characters to include in preview")
    source_read.add_argument("--hex-bytes", type=int, default=1024, help="Maximum binary bytes to include in hex preview")
    source_read.add_argument("--sqlite-table", help="Read a bounded page from a SQLite table instead of a generic file preview")
    source_read.add_argument("--sqlite-offset", type=int, default=0, help="SQLite table row offset for --sqlite-table")
    source_read.add_argument("--sqlite-limit", type=int, default=50, help="SQLite table row limit for --sqlite-table")
    source_read.add_argument("--sqlite-where-column", help="SQLite table column to filter with a contains match")
    source_read.add_argument("--sqlite-where-contains", help="SQLite table contains filter value for --sqlite-where-column")
    source_read.add_argument("--hash", action="store_true", help="Compute MD5/SHA1/SHA256 for the source file")
    source_read.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a compact preview")

    source_search = sub.add_parser(
        "source-search",
        help="Search inside one source file or ZIP entry from a completed run",
        description="Search inside one source file or ZIP entry from a completed run with bounded preview limits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage source-search ./rapidtriage-run-hacking --path Users/alice/Documents/note.txt -k password
              rapidtriage source-search ./rapidtriage-run-hacking --path Users/alice/Documents/ChatGPT-export.zip::conversations.json -k evtx --json
              rapidtriage source-search ./rapidtriage-run-hacking --path Users/alice/Logs/big.log -k error --byte-offset 2000000 --max-search-bytes 2000000
              rapidtriage source-search ./rapidtriage-run-hacking --path Users/alice/Databases/chat.sqlite -k invoice --sqlite-row-scan-limit 100000
            """
        ),
    )
    source_search.add_argument("run_output", help="Run output directory or rapidtriage-run-summary.json")
    source_search.add_argument("--path", required=True, help="Source file path, absolute, run-root relative, or archive.zip::entry")
    source_search.add_argument("-k", "--keyword", action="append", required=True, help="Keyword to search for")
    source_search.add_argument("--output", default="rapidtriage-source-search.json", help="JSON output path")
    source_search.add_argument("--limit", type=int, default=100, help="Maximum current-source matches")
    source_search.add_argument("--context", type=int, default=120, help="Characters of snippet context around each hit")
    source_search.add_argument("--max-chars", type=int, default=2_000_000, help="Maximum text characters to read from the source preview")
    source_search.add_argument("--byte-offset", type=int, default=0, help="Start byte offset for large plain-text source streaming")
    source_search.add_argument("--max-search-bytes", type=int, default=2_000_000, help="Maximum bytes to scan in a plain-text source window")
    source_search.add_argument("--sqlite-row-scan-limit", type=int, default=5_000, help="Maximum SQLite rows to scan across text columns")
    source_search.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a compact summary")

    ocr_queue = sub.add_parser(
        "ocr-queue",
        help="Build an OCR work queue for image candidates and sidecar imports",
        description="Scan image files, preserve OCR sidecar metadata, and produce retryable per-file OCR state",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage ocr-queue ./case-root --output rapidtriage-ocr-queue.json
              rapidtriage ocr-queue ./case-root --previous rapidtriage-ocr-queue.json --retry-failures --json
            """
        ),
    )
    ocr_queue.add_argument("root", help="Directory containing image evidence or extracted files")
    ocr_queue.add_argument("--output", default="rapidtriage-ocr-queue.json", help="OCR queue JSON output path")
    ocr_queue.add_argument("--previous", help="Previous OCR queue JSON for retry/status carry-forward")
    ocr_queue.add_argument("--retry-failures", action="store_true", help="Move previous failed items back to retry queue")
    ocr_queue.add_argument("--max-items", type=int, default=0, help="Cap scanned image candidates (0 means all)")
    ocr_queue.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    indicators = sub.add_parser(
        "indicators",
        help="Summarize URL, domain, IP, and hash indicators from a completed run",
        description="Summarize URL, domain, IP, and hash indicators from a completed run",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage indicators ./rapidtriage-run-fraud --output rapidtriage-indicators.json
              rapidtriage indicators ./rapidtriage-run-fraud/rapidtriage-run-summary.json --rules iocs.yaml
            """
        ),
    )
    indicators.add_argument("run_output", help="Run output directory or rapidtriage-run-summary.json")
    indicators.add_argument("--output", default="rapidtriage-indicators.json", help="JSON output path")
    indicators.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of indicators to keep (default 0 = uncapped; the cap is disclosed in summary.cap_policy)",
    )
    indicators.add_argument("--max-sources", type=int, default=10, help="Maximum source references per indicator")
    indicators.add_argument("--ti-feed", action="append", help="Local JSON/CSV/TXT threat-intel feed for offline IOC enrichment")
    indicators.add_argument("--json", action="store_true", help="Print JSON to stdout")
    add_rules_argument(indicators)


def register_run(sub: argparse._SubParsersAction) -> None:
    """Register case, run, run-plan, run-control."""
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
              rapidtriage run . --mode fraud --output-dir ../rapidtriage-run-fraud
              rapidtriage run /cases/image-mount --mode seizure --output-dir ./rapidtriage-run
              rapidtriage run /cases/image-mount --mode recovery --output-dir ./rapidtriage-run-recovery
              rapidtriage run /cases/image.E01 --mode fraud --output-dir ./rapidtriage-run-e01
              rapidtriage run . --mode hacking --output-dir ../rapidtriage-run-hacking --read-only --max-file-count 50
              rapidtriage run . --mode fraud --output-dir ../rapidtriage-run-fraud --extract
              rapidtriage run . --mode hacking --output-dir ../rapidtriage-run-hacking --skip-group messaging --skip-group mobile
              rapidtriage run . --mode hacking --print-plan
              rapidtriage run . --mode hacking --print-plan json

            --output-dir is required (except with --print-plan) and must be outside the
            evidence: never the evidence path, inside it, or a folder that contains it.
            출력 폴더(--output-dir)는 필수이며 증거 밖이어야 합니다 (증거 안·증거와 같은 경로·증거를 담은 폴더 불가).

            Run plan: the run is planned as groups -> tasks (rapidtriage-run-plan.json).
            Ctrl+C cancels everything still running but keeps the rows written so far,
            then writes the summary, report and audit record (exit code 130);
            press Ctrl+C again to stop at once. Use `rapidtriage run-control` from
            another terminal to cancel/skip one task or group, or to finish early.
            """
        ),
    )
    run.add_argument("root", help="Directory to triage")
    run.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    run.add_argument("--mode", required=True, choices=sorted(SUPPORTED_RUN_MODES), help="Incident mode to execute")
    run.add_argument(
        "--output-dir",
        help="Directory that receives the generated JSON, extract manifests (with --extract), "
        "and execution report. Required (except with --print-plan); must be outside the evidence "
        "(증거 밖의 출력 폴더 필수)",
    )
    run.add_argument("--dry-run", action="store_true", help="Skip evidence copying during extract stages")
    run.add_argument("--read-only", action="store_true", help="Run triage without copying evidence files during extract stages")
    run.add_argument("--extract", action="store_true", help="Copy and hash extraction candidates into docs-extract/ and files-extract/ (default: off)")
    run.add_argument("--max-extract-size-bytes", type=int, default=0, help="Cap total copied bytes per extract stage (0 means unlimited; requires --extract)")
    run.add_argument("--max-file-count", type=int, default=0, help="Cap run docs/files candidates and copied files per extract stage (0 means unlimited)")
    run.add_argument("--memory-cap-bytes", type=int, default=0, help="Stop the run at safe stage boundaries if RSS exceeds this value (0 also honors RAPIDTRIAGE_MEMORY_CAP_BYTES when set)")
    run.add_argument("--e01-partition-start-sector", type=int, help="Use this mmls partition start sector for direct E01/Ex01 or raw/split recovery instead of the automatic recommendation")
    run.add_argument("--overwrite", action="store_true", help="Allow extract stages to overwrite existing output files")
    run.add_argument("--resume", action="store_true", help="Reuse valid existing stage JSON outputs in OUTPUT_DIR and rerun missing or invalid stages")
    run.add_argument(
        "--known-good-hash-feed",
        action="append",
        default=[],
        help="Analyst-supplied MD5/SHA1/SHA256 known-good feed for the run file triage stage (TXT/CSV/JSON; repeatable)",
    )
    run.add_argument(
        "--hide-known-good",
        action="store_true",
        help="Hide known-good file candidates from the run Files output while preserving a suppression manifest",
    )
    run.add_argument(
        "--known-good-max-hash-bytes",
        type=int,
        default=64 * 1024 * 1024,
        help="Maximum file size to hash for run known-good checks (default: 67108864)",
    )
    run.add_argument(
        "--carve",
        action="store_true",
        help="Run an opt-in bounded signature-carving stage over the scan root and attach its summary to the run output",
    )
    run.add_argument(
        "--columnar-store",
        action="store_true",
        help="Write an opt-in columnar sidecar: stage ArtifactRecordV1 rows as JSONL and convert to Parquet for large-case query (requires pyarrow from the columnar extra; skipped when unavailable)",
    )
    run.add_argument(
        "--no-case-db",
        dest="case_db",
        action="store_false",
        help="Skip the persist step's run-local search index (rapidtriage-case.db); unified search then uses the bounded scan backend",
    )
    run.add_argument(
        "--skip-group",
        action="append",
        default=[],
        metavar="GROUP",
        help="Leave a run-plan group out before the run starts (repeatable; ids from --print-plan)",
    )
    run.add_argument(
        "--skip-task",
        action="append",
        default=[],
        metavar="TASK",
        help="Leave one run-plan task (provider kind or stage) out before the run starts (repeatable)",
    )
    run.add_argument(
        "--artifact-kinds",
        "--only-kinds",
        dest="artifact_kinds",
        default="",
        metavar="K1,K2",
        help="Run only these artifact kinds (comma-separated, e.g. ai-agent). Every other provider and the "
        "tree-walking docs/files/carve/extract stages are skipped, and the input fingerprint is sampled "
        "(path/size/mtime of the first files, no content hash); the run summary records the restriction",
    )
    run.add_argument(
        "--ai-read-mb",
        type=int,
        default=None,
        metavar="MB",
        help="ai-agent: per-adapter read budget in MiB for parsed session files, newest first "
        "(default: RAPIDTRIAGE_AI_READ_MB or 4096); files left out are listed in rapidtriage-ai-agent-skipped.json",
    )
    run.add_argument(
        "--print-plan",
        nargs="?",
        const="table",
        choices=("table", "json"),
        help="Print the run plan (groups -> tasks) for these options and exit without running",
    )
    add_eventlog_output_arguments(run)
    add_rules_argument(run)

    run_plan = sub.add_parser(
        "run-plan",
        help="Show the run plan (groups -> tasks, status, rows, durations) of a run output directory",
        description="Show the run plan of a running or finished run (rapidtriage-run-progress.json / rapidtriage-run-plan.json)",
    )
    run_plan.add_argument("output_dir", help="Run output directory")
    run_plan.add_argument("--json", action="store_true", help="Print the plan JSON instead of a table")

    run_control = sub.add_parser(
        "run-control",
        help="Cancel or skip a task/group of a running run, cancel everything, or finish early",
        description="Write a request to OUTPUT_DIR/rapidtriage-run-control.json; the run applies it within a second",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage run-control ./run-out cancel --target task:eventlog
              rapidtriage run-control ./run-out skip --target group:messaging
              rapidtriage run-control ./run-out cancel        (= cancel-all)
              rapidtriage run-control ./run-out finish
            """
        ),
    )
    run_control.add_argument("output_dir", help="Run output directory")
    run_control.add_argument("action", choices=("cancel", "skip", "finish", "cancel-all"), help="Control action")
    run_control.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="group:ID|task:ID",
        help="Task or group to cancel/skip (repeatable); `cancel` without a target cancels everything",
    )
