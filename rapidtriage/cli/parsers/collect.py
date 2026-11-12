"""Parser registration for collection and source-listing commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.artifacts import SUPPORTED_ARTIFACT_KINDS
from ...core.cloud_api import (
    DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
    DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
    DEFAULT_CLOUD_BEARER_TOKEN_ENV,
)
from ...core.collect_plan import (
    DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT,
    DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES,
    supported_collect_profiles,
)
from ...core.input_root import SUPPORTED_INPUT_ROOT_KINDS
from ..helpers import (
    add_eventlog_output_arguments,
    add_rules_argument,
)


def register_sources(sub: argparse._SubParsersAction) -> None:
    """Register docs, docs-index-search, manifest, artifacts, email-external-parse, taxonomy-audit."""
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

    docs_index_search = sub.add_parser(
        "docs-index-search",
        help="Query a processed-text docs-index sidecar without re-extracting document text",
        description="Query a processed-text docs-index sidecar without re-extracting document text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage docs-index-search rapidtriage-docs-index.json -k password
              rapidtriage docs-index-search rapidtriage-docs-index.json incident credential --limit 100 --json
            """
        ),
    )
    docs_index_search.add_argument("index", help="Path to a docs-index JSON sidecar")
    docs_index_search.add_argument("terms", nargs="*", help="Optional positional query terms")
    docs_index_search.add_argument("-k", "--keyword", action="append", help="Keyword or term to search")
    docs_index_search.add_argument("--limit", type=int, default=500, help="Maximum result rows to return (capped at 5000)")
    docs_index_search.add_argument("--output", default="rapidtriage-docs-index-search.json", help="JSON output path")
    docs_index_search.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

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
    artifacts.add_argument(
        "--eventlog-message-catalog",
        help="JSON provider/event message catalog for --kind eventlog rendering",
    )
    artifacts.add_argument(
        "--ai-read-mb",
        type=int,
        default=None,
        metavar="MB",
        help="ai-agent: per-adapter read budget in MiB for parsed session files, newest first "
        "(default: RAPIDTRIAGE_AI_READ_MB or 4096); files left out are listed in rapidtriage-ai-agent-skipped.json",
    )
    add_eventlog_output_arguments(artifacts)
    add_rules_argument(artifacts)

    email_external = sub.add_parser(
        "email-external-parse",
        help="Run optional external PST/OST/MSG parser wrappers and record evidence",
        description="Use pffexport/readpst/msg-extractor when available to export mailbox objects for trusted-diff validation",
    )
    email_external.add_argument("source", help="Path to PST, OST, or MSG file")
    email_external.add_argument("--output-dir", required=True, help="Directory for parser JSON, Markdown, and exported files")
    email_external.add_argument("--preferred-tool", help="Preferred parser command, e.g. pffexport, readpst, msg-extractor")
    email_external.add_argument("--timeout-seconds", type=int, default=300, help="External parser timeout")
    email_external.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty parser output directory")
    email_external.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    taxonomy_audit = sub.add_parser(
        "taxonomy-audit",
        help="Audit target forensic artifact coverage against collectors, artifact types, viewers, tests, and docs",
        description=(
            "Audit target forensic artifact coverage so Maestro-style missing artifact families are visible "
            "instead of being hidden behind broad collector counts"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage taxonomy-audit --json
              rapidtriage taxonomy-audit --output rapidtriage-taxonomy-audit.json --strict
            """
        ),
    )
    taxonomy_audit.add_argument("--repo-root", default=".", help="Repository root to audit (default: current directory)")
    taxonomy_audit.add_argument("--output", default="rapidtriage-taxonomy-audit.json", help="JSON output path")
    taxonomy_audit.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    taxonomy_audit.add_argument("--strict", action="store_true", help="Return exit code 1 when any taxonomy target is incomplete")


def register_cloud(sub: argparse._SubParsersAction) -> None:
    """Register cloud-collect."""
    cloud_collect = sub.add_parser(
        "cloud-collect",
        help="Collect authorized cloud API JSON responses from a request manifest",
        description="Collect authorized cloud API JSON responses from a request manifest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage cloud-collect ./cloud-api-manifest.json --output-dir ./cloud-api-raw
              RAPIDTRIAGE_CLOUD_BEARER_TOKEN=... rapidtriage cloud-collect ./manifest.json --output-dir ./cloud-api-raw
              rapidtriage artifacts ./cloud-api-raw/responses --kind cloud-export --output cloud-artifacts.json
            """
        ),
    )
    cloud_collect.add_argument("manifest", help="JSON manifest describing authorized API requests")
    cloud_collect.add_argument("--output-dir", required=True, help="Directory for raw responses and collection manifest")
    cloud_collect.add_argument(
        "--bearer-token-env",
        default=DEFAULT_CLOUD_BEARER_TOKEN_ENV,
        help=f"Environment variable containing a Bearer token (default: {DEFAULT_CLOUD_BEARER_TOKEN_ENV})",
    )
    cloud_collect.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
        help=f"Per-request timeout in seconds (default: {DEFAULT_CLOUD_API_TIMEOUT_SECONDS})",
    )
    cloud_collect.add_argument(
        "--max-response-bytes",
        type=int,
        default=DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
        help="Maximum bytes to keep per response before marking it truncated",
    )
    cloud_collect.add_argument("--allow-insecure-http", action="store_true", help="Allow non-local HTTP URLs")
    cloud_collect.add_argument("--dry-run", action="store_true", help="Validate and summarize requests without sending them")


def register_plans(sub: argparse._SubParsersAction) -> None:
    """Register known-good-index, collect-plan, collect-export."""
    known_good_index = sub.add_parser(
        "known-good-index",
        help="Build a reusable local known-good/NSRL hash index JSON",
        description="Build a reusable local known-good/NSRL hash index JSON from TXT/CSV/JSON/ZIP feeds or feed directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage known-good-index ./NSRLFile.txt --output known-good-index.json
              rapidtriage known-good-index ./NSRL-RDS.zip --output known-good-index.json
              rapidtriage known-good-index ./feeds-dir --output case-known-good-index.json --json
              rapidtriage files ./case --known-good-hash-feed ./known-good-index.json --hide-known-good
            """
        ),
    )
    known_good_index.add_argument("feed", nargs="+", help="Known-good feed file or directory (TXT/CSV/JSON/ZIP; repeatable)")
    known_good_index.add_argument("--output", default="known-good-index.json", help="Normalized index JSON output path")
    known_good_index.add_argument("--json", action="store_true", help="Print index JSON after saving it")

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
