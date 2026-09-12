"""Argparse parser construction for the rapidtriage CLI."""

from __future__ import annotations

import argparse
import textwrap

from ..artifacts.kakaotalk_macos import (
    DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS,
    DEFAULT_MACOS_REPORT_MAX_MESSAGES,
)
from ..core.artifacts import SUPPORTED_ARTIFACT_KINDS
from ..core.benchmark import DEFAULT_BENCHMARK_FILE_COUNT, DEFAULT_BENCHMARK_KEYWORD
from ..core.benchmark_fts import (
    SQLITE_FTS_DEFAULT_HIT_EVERY,
    SQLITE_FTS_DEFAULT_QUERY_ITERATIONS,
    SQLITE_FTS_DEFAULT_RECORD_COUNT,
)
from ..core.browser_stress import DEFAULT_BROWSER_STRESS_RECORD_COUNT
from ..core.carving import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_CARVE_BYTES,
    DEFAULT_MAX_SCAN_BYTES,
)
from ..core.case import REVIEW_STATUSES
from ..core.case_catalog import default_case_catalog_path
from ..core.cloud_api import (
    DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
    DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
    DEFAULT_CLOUD_BEARER_TOKEN_ENV,
)
from ..core.collect_plan import (
    DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT,
    DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES,
    supported_collect_profiles,
)
from ..core.commercial_readiness import MATURITY_GATE_ORDER
from ..core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, SUPPORTED_DOC_KINDS
from ..core.files import ALL_FILE_CATEGORIES
from ..core.forensic_validation_plan import (
    DEFAULT_FORENSIC_VALIDATION_ITEMS,
    DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
)
from ..core.input_root import SUPPORTED_INPUT_ROOT_KINDS
from ..core.kakaotalk import (
    DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
    DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT,
    DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
    DEFAULT_MEMORY_SQLITE_MAX_HITS,
)
from ..core.large_case_readiness import DEFAULT_LARGE_CASE_P95_THRESHOLD_MS
from ..core.macos_live_smoke import (
    DEFAULT_MACOS_SMOKE_BENCHMARK_FILES,
    DEFAULT_MACOS_SMOKE_FTS_RECORDS,
)
from ..core.run import SUPPORTED_RUN_MODES
from ..core.sample_case import DEFAULT_SAMPLE_DIR, DEFAULT_SAMPLE_MODE
from ..core.validation_diff_runners import VERSION_PROBE_TIMEOUT_SECONDS
from .helpers import add_rules_argument, add_web_arguments

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
              rapidtriage docs-index-search rapidtriage-docs-index.json -k incident
              rapidtriage files . --output rapidtriage-files.json
              rapidtriage collect-plan /Volumes/case-mount --profile intrusion --output rapidtriage-collect-plan.json
              rapidtriage collect-export /Volumes/case-mount ./collect-export --profile intrusion --copy
              rapidtriage compare ./before.txt ./after.txt --output compare.json
              rapidtriage vsc-compare ./current ./vss/snapshot-1 --output vsc-delta.json
              rapidtriage carve /cases/image-mount --output-dir ./carve-review --extract
              rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
              rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
              rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
              rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage cloud-collect ./cloud-api-manifest.json --output-dir ./cloud-api-raw
              rapidtriage timeline . --output rapidtriage-timeline.json --report rapidtriage-timeline-report.md
              rapidtriage case ./incident-case.json --source rapidtriage-timeline.json --pointer /events/0 --tag suspicious
              rapidtriage manifest /Volumes/case-mount --input-kind mounted-image
              rapidtriage run . --mode fraud --output-dir ./rapidtriage-run --read-only
              rapidtriage run ./case.E01 --mode fraud --output-dir ./rapidtriage-run-e01
              rapidtriage search ./rapidtriage-run-fraud -k invoice -k password
              rapidtriage indicators ./rapidtriage-run-fraud --output rapidtriage-indicators.json
              rapidtriage sample --run --overwrite
              rapidtriage case-db ./rapidtriage-case.db --create-case CASE-001 --name "Case 001"
              rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password
              rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant --verification-status source_opened
              rapidtriage case-db-report ./rapidtriage-case.db --case-id CASE-001 --output report-candidates.json
              rapidtriage evidence ./case.E01
              rapidtriage benchmark --output-dir ./rapidtriage-benchmark --file-count 1000
              rapidtriage validation --output-dir ./rapidtriage-validation --overwrite
              rapidtriage commercial-readiness --output-dir ./commercial-readiness --json
              rapidtriage cross-tool-validate --rapid-output rapidtriage-artifacts-eventlog.json --reference-output evtxecmd=EvtxECmd.csv
              rapidtriage confidence-dashboard ./rapidtriage-run --json
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

    kakao_decrypt = sub.add_parser(
        "kakaotalk-decrypt",
        help="Decrypt authorized Windows KakaoTalk chatLogs_*.edb files and summarize message tables",
        description="Decrypt authorized Windows KakaoTalk chatLogs_*.edb files and summarize message tables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              RAPIDTRIAGE_KAKAO_KEY_HEX=... RAPIDTRIAGE_KAKAO_IV_HEX=... rapidtriage kakaotalk-decrypt ./KakaoTalk --output kakao-decrypt.json
              RAPIDTRIAGE_KAKAO_PRAGMA=... RAPIDTRIAGE_KAKAO_USER_ID=12345 rapidtriage kakaotalk-decrypt ./KakaoTalk --include-message-preview
            """
        ),
    )
    kakao_decrypt.add_argument("root", help="Extracted KakaoTalk user/app-data folder to scan")
    kakao_decrypt.add_argument("--output", default="rapidtriage-kakaotalk-decrypt.json", help="JSON output path")
    kakao_decrypt.add_argument("--key-hex", help="Authorized 16-byte AES key as hex; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--iv-hex", help="Authorized 16-byte AES IV as hex; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--key-hex-env", default="RAPIDTRIAGE_KAKAO_KEY_HEX", help="Environment variable for AES key hex")
    kakao_decrypt.add_argument("--iv-hex-env", default="RAPIDTRIAGE_KAKAO_IV_HEX", help="Environment variable for AES IV hex")
    kakao_decrypt.add_argument("--pragma", help="Authorized KakaoTalk pragma value; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--user-id", help="Authorized KakaoTalk userId paired with pragma; prefer env")
    kakao_decrypt.add_argument("--pragma-key-hex", help="Authorized 16-byte DeviceInfo pragma-generation key as hex")
    kakao_decrypt.add_argument("--sys-uuid", help="Override DeviceInfo sys_uuid; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--hdd-model", help="Override DeviceInfo hdd_model; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--hdd-serial", help="Override DeviceInfo hdd_serial; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--pragma-env", default="RAPIDTRIAGE_KAKAO_PRAGMA", help="Environment variable for pragma")
    kakao_decrypt.add_argument("--user-id-env", default="RAPIDTRIAGE_KAKAO_USER_ID", help="Environment variable for userId")
    kakao_decrypt.add_argument("--pragma-key-hex-env", default="RAPIDTRIAGE_KAKAO_PRAGMA_KEY_HEX", help="Environment variable for DeviceInfo pragma-generation key hex")
    kakao_decrypt.add_argument("--sys-uuid-env", default="RAPIDTRIAGE_KAKAO_SYS_UUID", help="Environment variable for DeviceInfo sys_uuid")
    kakao_decrypt.add_argument("--hdd-model-env", default="RAPIDTRIAGE_KAKAO_HDD_MODEL", help="Environment variable for DeviceInfo hdd_model")
    kakao_decrypt.add_argument("--hdd-serial-env", default="RAPIDTRIAGE_KAKAO_HDD_SERIAL", help="Environment variable for DeviceInfo hdd_serial")
    kakao_decrypt.add_argument("--include-message-preview", action="store_true", help="Include bounded raw message previews in JSON")
    kakao_decrypt.add_argument("--write-decrypted", action="store_true", help="Write decrypted SQLite files to --decrypted-dir")
    kakao_decrypt.add_argument("--decrypted-dir", help="Directory for decrypted SQLite files when --write-decrypted is set")
    kakao_decrypt.add_argument("--max-databases", type=int, default=0, help="Limit chatLogs databases processed (0 means all)")
    kakao_decrypt.add_argument("--max-messages-per-db", type=int, default=20, help="Bounded preview rows per database")
    kakao_decrypt.add_argument("--openssl-bin", default="openssl", help="OpenSSL binary used for AES-CBC pages")
    kakao_decrypt.add_argument(
        "--no-postpatch-memory-carve",
        action="store_true",
        help="Disable fallback SQLite carving from KakaoTalk process memory dumps when legacy decrypt fails",
    )
    kakao_decrypt.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_macos_report = sub.add_parser(
        "kakaotalk-macos-report",
        help="Export authorized macOS KakaoTalk messages into CSV and a static HTML viewer",
        description=(
            "Build a reviewable macOS KakaoTalk report package from a Mac home, mounted Mac root, "
            "KakaoTalk container, or extracted collection folder"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-macos-report ~/Library/Containers/com.kakao.KakaoTalkMac --output-dir ./kakao-mac-report
              RAPIDTRIAGE_KAKAO_MAC_USER_ID=12345 RAPIDTRIAGE_KAKAO_MAC_UUID=... rapidtriage kakaotalk-macos-report /Volumes/MacHD --output-dir ./kakao-mac-report --include-message-text
            """
        ),
    )
    kakao_macos_report.add_argument("root", help="Mac home, mounted Mac root, KakaoTalk container, or extracted folder")
    kakao_macos_report.add_argument("--output-dir", required=True, help="Directory for JSON, CSV, and HTML report outputs")
    kakao_macos_report.add_argument(
        "--include-message-text",
        action="store_true",
        help="Include raw message/body fields in CSV and HTML; default exports hashes/lengths only",
    )
    kakao_macos_report.add_argument(
        "--max-messages",
        type=int,
        default=DEFAULT_MACOS_REPORT_MAX_MESSAGES,
        help=f"Maximum message rows to export ({DEFAULT_MACOS_REPORT_MAX_MESSAGES} default, 0 means all)",
    )
    kakao_macos_report.add_argument(
        "--max-context-rows",
        type=int,
        default=DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS,
        help=(
            "Maximum room/user context rows to export per context table "
            f"({DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS} default, 0 means all)"
        ),
    )
    kakao_macos_report.add_argument(
        "--user-id-file",
        help="File containing an authorized macOS KakaoTalk numeric UserID; value is read in-memory and not exported",
    )
    kakao_macos_report.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary for encrypted stores")
    kakao_macos_report.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_collect = sub.add_parser(
        "kakaotalk-collect-windows",
        help="Collect authorized Windows PC KakaoTalk data into a ZIP and optionally analyze it",
        description="Collect authorized Windows PC KakaoTalk data into a ZIP and optionally run the KakaoTalk SQLCipher/report workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-collect-windows --output-root ./cases --analyze --no-xlsx
              rapidtriage kakaotalk-collect-windows --kakao-root "C:\\Users\\USER\\AppData\\Local\\Kakao\\KakaoTalk" --output-root D:\\Cases
              rapidtriage kakaotalk-collect-windows --include-memory-dump --analyze --sqlcipher-bin C:\\Tools\\sqlcipher.exe
            """
        ),
    )
    kakao_collect.add_argument("--output-root", default="kakaotalk_auto_cases", help="Directory where collection case folders are created")
    kakao_collect.add_argument("--kakao-root", help="Override KakaoTalk root; default is %%LOCALAPPDATA%%\\Kakao\\KakaoTalk on Windows")
    kakao_collect.add_argument("--include-memory-dump", action="store_true", help="Also attempt a KakaoTalk.exe memory dump; may require Administrator")
    kakao_collect.add_argument("--analyze", action="store_true", help="Run post-patch SQLCipher/message/media analysis after collection")
    kakao_collect.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary used when --analyze is set")
    kakao_collect.add_argument("--timeout-seconds", type=float, default=5.0, help="Timeout per SQLCipher probe when --analyze is set")
    kakao_collect.add_argument("--max-message-residues", type=int, default=1000, help="Maximum memory message residues when --analyze is set")
    kakao_collect.add_argument("--no-xlsx", action="store_true", help="Record that XLSX output should be skipped by wrapper tooling")
    kakao_collect.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_memory_carve = sub.add_parser(
        "kakaotalk-memory-carve",
        help="Carve decrypted SQLite residues from authorized KakaoTalk process memory dumps",
        description="Carve decrypted SQLite residues from authorized KakaoTalk process memory dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-memory-carve ./KakaoTalk --output kakao-memory-carve.json
              rapidtriage kakaotalk-memory-carve ./KakaoTalk --write-carves --carve-dir ./memory-carves
            """
        ),
    )
    kakao_memory_carve.add_argument("root", help="Extracted KakaoTalk folder containing KakaoTalk.DMP or memory dumps")
    kakao_memory_carve.add_argument("--output", default="rapidtriage-kakaotalk-memory-carve.json", help="JSON output path")
    kakao_memory_carve.add_argument("--carve-dir", help="Directory for carved SQLite files when --write-carves is set")
    kakao_memory_carve.add_argument("--write-carves", action="store_true", help="Write carved SQLite fragments to --carve-dir")
    kakao_memory_carve.add_argument("--max-hits", type=int, default=DEFAULT_MEMORY_SQLITE_MAX_HITS, help="Maximum SQLite headers to carve (0 means all)")
    kakao_memory_carve.add_argument("--max-carve-bytes", type=int, default=DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES, help="Maximum bytes to carve for one SQLite header")
    kakao_memory_carve.add_argument("--include-row-preview", action="store_true", help="Include bounded row previews when readable")
    kakao_memory_carve.add_argument("--include-message-preview", action="store_true", help="Include process-memory chat message body previews")
    kakao_memory_carve.add_argument("--message-csv", help="Optional UTF-8-SIG CSV path for process-memory chat message body residues")
    kakao_memory_carve.add_argument("--max-rows-per-table", type=int, default=3, help="Bounded row previews per table")
    kakao_memory_carve.add_argument(
        "--max-message-residues",
        type=int,
        default=DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
        help="Maximum process-memory chat JSON message residues to report (0 means all)",
    )
    kakao_memory_carve.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_sqlcipher_probe = sub.add_parser(
        "kakaotalk-sqlcipher-probe",
        help="Probe post-patch KakaoTalk chatLogs_*.edb with redacted SQLCipher key residues from memory",
        description="Probe post-patch KakaoTalk chatLogs_*.edb with redacted SQLCipher key residues from memory",
    )
    kakao_sqlcipher_probe.add_argument("root", help="Extracted KakaoTalk folder containing chatLogs_*.edb and memory dumps")
    kakao_sqlcipher_probe.add_argument("--output", default="rapidtriage-kakaotalk-sqlcipher-probe.json", help="JSON output path")
    kakao_sqlcipher_probe.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary to use for temp-copy probes")
    kakao_sqlcipher_probe.add_argument("--max-keys", type=int, default=DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT, help="Maximum unique SQLCipher key residues to test (0 means all)")
    kakao_sqlcipher_probe.add_argument("--max-databases", type=int, default=0, help="Maximum chatLogs databases to test (0 means all)")
    kakao_sqlcipher_probe.add_argument("--max-message-residues", type=int, default=DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT, help="Maximum post-patch message JSON residues to collect from memory (0 means all)")
    kakao_sqlcipher_probe.add_argument("--include-message-preview", action="store_true", help="Include recovered message text previews in JSON output")
    kakao_sqlcipher_probe.add_argument("--timeout-seconds", type=float, default=2.0, help="Timeout per SQLCipher key/database/compatibility probe")
    kakao_sqlcipher_probe.add_argument("--export-opened-dir", help="Optional directory to export SQLCipher-openable EDBs as plaintext SQLite")
    kakao_sqlcipher_probe.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_key_store = sub.add_parser(
        "kakaotalk-key-store-inspect",
        help="Inspect post-patch KakaoTalk appstate.dat wrapped-DEK key stores without exporting secrets",
        description="Inspect post-patch KakaoTalk appstate.dat wrapped-DEK key stores without exporting secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-key-store-inspect ./KakaoTalk --output kakao-key-store.json
              rapidtriage kakaotalk-key-store-inspect ./KakaoTalk --max-memory-sources 1 --json
            """
        ),
    )
    kakao_key_store.add_argument("root", help="Extracted KakaoTalk folder containing appstate.dat and chatLogs_*.edb")
    kakao_key_store.add_argument("--output", default="rapidtriage-kakaotalk-key-store.json", help="JSON output path")
    kakao_key_store.add_argument("--max-memory-sources", type=int, default=2, help="Maximum memory dumps to check for key-store residency (0 disables memory checks)")
    kakao_key_store.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_userdir = sub.add_parser(
        "kakaotalk-userdir-bruteforce",
        help="Find an authorized Windows KakaoTalk userId from a users/<userDir> folder name",
        description="Find an authorized Windows KakaoTalk userId from a users/<userDir> folder name",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-userdir-bruteforce ./KakaoTalk --userdir-home "C:\\Users\\USER\\AppData\\Local\\Kakao\\KakaoTalk\\users" --pragma-key-hex ...
              rapidtriage kakaotalk-userdir-bruteforce ./KakaoTalk --pragma ... --start-id 1 --end-id 400000000 --chunk-size 10000000
            """
        ),
    )
    kakao_userdir.add_argument("root", help="Extracted KakaoTalk user/app-data folder to scan")
    kakao_userdir.add_argument("--output", default="rapidtriage-kakaotalk-userdir-bruteforce.json", help="JSON output path")
    kakao_userdir.add_argument("--userdir", help="40-hex users/<userDir> folder name; inferred when omitted")
    kakao_userdir.add_argument("--userdir-home", help=r'Original Windows users path, e.g. C:\Users\USER\AppData\Local\Kakao\KakaoTalk\users')
    kakao_userdir.add_argument("--pragma", help="Authorized KakaoTalk pragma value; prefer env/file handling outside shell history")
    kakao_userdir.add_argument("--pragma-key-hex", help="Authorized 16-byte DeviceInfo pragma-generation key as hex")
    kakao_userdir.add_argument("--sys-uuid", help="Override DeviceInfo sys_uuid; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--hdd-model", help="Override DeviceInfo hdd_model; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--hdd-serial", help="Override DeviceInfo hdd_serial; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--start-id", type=int, default=1, help="First numeric userId to test")
    kakao_userdir.add_argument("--end-id", type=int, default=400_000_000, help="Last numeric userId to test")
    kakao_userdir.add_argument("--chunk-size", type=int, default=10_000_000, help="Range size per checkpointed native-helper run")
    kakao_userdir.add_argument("--compiler", default="cc", help="C compiler for the native CommonCrypto accelerator")
    kakao_userdir.add_argument("--openssl-bin", default="openssl", help="OpenSSL binary used for DeviceInfo pragma derivation checks")
    kakao_userdir.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

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

    vsc_discover = sub.add_parser(
        "vsc-discover",
        help="Discover likely mounted/exported Volume Shadow Copy snapshot folders",
        description="Discover likely VSC snapshot folders near a mounted/exported current volume root",
    )
    vsc_discover.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_discover.add_argument("--output", default="rapidtriage-vsc-discovery.json", help="JSON output path")
    vsc_discover.add_argument("--max-depth", type=int, default=3, help="Maximum directory depth to inspect around the current root")
    vsc_discover.add_argument("--json", action="store_true", help="Print the full JSON discovery report after saving it")

    vsc_extract = sub.add_parser(
        "vsc-extract",
        help="Copy deleted/modified Volume Shadow Copy candidates into an evidence package",
        description="Compare current files against VSC snapshot folders and copy selected snapshot/current files with hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage vsc-extract ./current ./vss/snapshot-1 --output-dir ./vsc-evidence
              rapidtriage vsc-extract ./current ./vss/snapshot-1 --status deleted --status modified --max-file-count 500
            """
        ),
    )
    vsc_extract.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_extract.add_argument("snapshot_roots", nargs="+", help="One or more VSC snapshot file trees to compare/extract")
    vsc_extract.add_argument("--output-dir", required=True, help="Directory that receives rapidtriage-vsc-extract.json and copied evidence")
    vsc_extract.add_argument("--manifest", help="Manifest JSON output path (default: OUTPUT_DIR/rapidtriage-vsc-extract.json)")
    vsc_extract.add_argument("--status", action="append", choices=["deleted", "modified", "added"], help="Change status to copy; repeatable. Defaults to deleted+modified")
    vsc_extract.add_argument("--no-hash", action="store_true", help="Skip comparison-time hashing; copied files are still hashed after copy")
    vsc_extract.add_argument("--case-sensitive", action="store_true", help="Compare paths case-sensitively")
    vsc_extract.add_argument("--overwrite", action="store_true", help="Allow overwriting existing files in OUTPUT_DIR/evidence")
    vsc_extract.add_argument("--max-records", type=int, default=10000, help="Maximum change records per snapshot (0 means unlimited)")
    vsc_extract.add_argument("--max-file-count", type=int, default=1000, help="Maximum files to copy (0 means unlimited)")
    vsc_extract.add_argument("--max-total-bytes", type=int, default=2 * 1024 * 1024 * 1024, help="Maximum copied source bytes (0 means unlimited)")
    vsc_extract.add_argument("--json", action="store_true", help="Print the full JSON extraction manifest after saving it")

    carve = sub.add_parser(
        "carve",
        help="Run bounded signature carving for deleted/recovered file candidates",
        description="Run bounded signature carving for deleted/recovered file candidates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage carve /cases/image-mount --output-dir ./carve-review
              rapidtriage carve disk.raw --output-dir ./carve-review --extract --max-candidates 50
            """
        ),
    )
    carve.add_argument("root", help="Mounted/exported folder or file to scan for carved candidates")
    carve.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    carve.add_argument("--output-dir", required=True, help="Directory that receives rapidtriage-carve.json and optional carved files")
    carve.add_argument("--extract", action="store_true", help="Write carved candidate bytes under OUTPUT_DIR/carved")
    carve.add_argument("--max-scan-bytes", type=int, default=DEFAULT_MAX_SCAN_BYTES, help="Maximum bytes to inspect per source file")
    carve.add_argument("--max-carve-bytes", type=int, default=DEFAULT_MAX_CARVE_BYTES, help="Maximum bytes to copy for one carved candidate")
    carve.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES, help="Maximum carving candidates to report")
    carve.add_argument("--ext", action="append", help="Only scan source files with this extension (repeatable)")
    carve.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    indicators.add_argument("--limit", type=int, default=1000, help="Maximum number of indicators to keep")
    indicators.add_argument("--max-sources", type=int, default=10, help="Maximum source references per indicator")
    indicators.add_argument("--ti-feed", action="append", help="Local JSON/CSV/TXT threat-intel feed for offline IOC enrichment")
    indicators.add_argument("--json", action="store_true", help="Print JSON to stdout")
    add_rules_argument(indicators)

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

    enterprise_policy = sub.add_parser(
        "enterprise-policy",
        help="Print local-only enterprise/security policy status",
        description="Print local-only enterprise policy status for telemetry, license, RBAC, and collaboration readiness",
    )
    enterprise_policy.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    rearchitecture_status = sub.add_parser(
        "rearchitecture-status",
        help="Evaluate Python/Rust commercial re-architecture progress",
        description="Evaluate the staged Python/Rust re-architecture plan, worker foundation, storage foundation, and local blockers",
    )
    rearchitecture_status.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    worker_parse = sub.add_parser(
        "worker-parse",
        help="Run an isolated Rust parser worker and store ArtifactRecordV1 JSONL",
        description="Run rapid-worker as an isolated parser process and stream normalized ArtifactRecordV1 rows to JSONL",
    )
    worker_parse.add_argument("source", help="Evidence source path for the worker")
    worker_parse.add_argument("--kind", required=True, help="Worker parser kind, e.g. noop or file-inventory")
    worker_parse.add_argument("--output", required=True, help="ArtifactRecordV1 JSONL output path")
    worker_parse.add_argument("--worker", help="Path to rapid-worker executable; defaults to RAPIDTRIAGE_RUST_WORKER or PATH")
    worker_parse.add_argument("--case-id", default="CASE", help="Case ID to pass to the worker")
    worker_parse.add_argument("--source-id", default="SOURCE", help="Source ID to pass to the worker")
    worker_parse.add_argument("--timeout-seconds", type=float, default=30.0, help="Worker timeout in seconds")
    worker_parse.add_argument("--extra-arg", action="append", default=[], help="Extra raw argument for the worker; repeat as needed")
    worker_parse.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    evidence.add_argument("--output", help="Optional JSON output path for the evidence preflight/runbook")
    evidence.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_known_answer = sub.add_parser(
        "e01-known-answer",
        help="Build a Windows 11 E01 known-answer manifest draft",
        description="Build a Windows 11 E01 known-answer manifest draft for single-case validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage e01-known-answer ./case.E01 --output ./windows11-e01-known-answer.json
              rapidtriage e01-known-answer ./case.E01 --case-id CASE-001 --expected-partition-start-sector 2048 --expected-artifact "Security.evtx event 4624"
            """
        ),
    )
    e01_known_answer.add_argument("source", help="Windows 11 E01/Ex01 source image")
    e01_known_answer.add_argument("--case-id", default="windows11-e01-known-answer", help="Case identifier for the manifest")
    e01_known_answer.add_argument("--expected-partition-start-sector", type=int, help="Expected Windows filesystem start sector")
    e01_known_answer.add_argument("--expected-artifact", action="append", default=[], help="Expected high-value artifact assertion; repeatable")
    e01_known_answer.add_argument("--validation-command", action="append", default=[], help="Validation command to preserve in the manifest; repeatable")
    e01_known_answer.add_argument("--output", help="Optional JSON output path")
    e01_known_answer.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_smoke = sub.add_parser(
        "e01-smoke",
        help="Run a Windows 11 E01 single-case workflow smoke report",
        description="Run a Windows 11 E01 workflow smoke report from preflight through report generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage e01-smoke ./case.E01 --output-dir ./case-smoke --case-id CASE-001
              rapidtriage e01-smoke ./case.E01 --output-dir ./case-smoke --expected-partition-start-sector 2048 --plan-only
            """
        ),
    )
    e01_smoke.add_argument("source", help="Windows 11 E01/Ex01 source image")
    e01_smoke.add_argument("--output-dir", required=True, help="Directory for smoke report outputs")
    e01_smoke.add_argument("--case-id", default="windows11-e01-smoke", help="Case identifier for the smoke report")
    e01_smoke.add_argument("--mode", choices=sorted(SUPPORTED_RUN_MODES), default="hacking", help="Run mode for artifact triage")
    e01_smoke.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    e01_smoke.add_argument("--expected-partition-start-sector", type=int, help="Expected Windows filesystem start sector")
    e01_smoke.add_argument("--expected-artifact", action="append", default=[], help="Expected high-value artifact assertion; repeatable")
    e01_smoke.add_argument("--validation-command", action="append", default=[], help="Validation command to preserve in the manifest; repeatable")
    e01_smoke.add_argument("--plan-only", action="store_true", help="Write preflight/known-answer files without attempting extraction")
    e01_smoke.add_argument("--write-extracts", action="store_true", help="Allow extracted files to be written during the run stage")
    e01_smoke.add_argument("--resume", action="store_true", help="Reuse resumable stage outputs when possible")
    e01_smoke.add_argument("--max-file-count", type=int, default=0, help="Maximum extracted file count during run stage")
    e01_smoke.add_argument("--max-extract-size-bytes", type=int, default=0, help="Maximum extracted byte budget during run stage")
    e01_smoke.add_argument("--memory-cap-bytes", type=int, default=0, help="Soft memory cap for run stages")
    e01_smoke.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_hash = sub.add_parser(
        "e01-hash",
        help="Compute streaming full-image hashes for E01/Ex01 evidence files",
        description="Compute SHA256/SHA1/MD5 over the selected evidence image with progress checkpoints for report-grade hash evidence",
    )
    e01_hash.add_argument("source", help="Path to the E01/Ex01 or raw image file to hash")
    e01_hash.add_argument("--output-dir", required=True, help="Directory for hash JSON, Markdown, and checkpoint outputs")
    e01_hash.add_argument("--algorithm", action="append", help="Hash algorithm to compute; repeatable; defaults to sha256/sha1/md5")
    e01_hash.add_argument("--chunk-size", type=int, default=8 * 1024 * 1024, help="Read chunk size in bytes")
    e01_hash.add_argument("--checkpoint-interval-bytes", type=int, default=128 * 1024 * 1024, help="Bytes between checkpoint writes")
    e01_hash.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty hash output directory")
    e01_hash.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    benchmark.add_argument("--resume", action="store_true", help="Reuse valid benchmark run outputs when the input fingerprint is unchanged")
    benchmark.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    macos_live_smoke = sub.add_parser(
        "macos-live-smoke",
        help="Run redacted local macOS artifact, performance, and validation-tool smoke evidence",
        description=(
            "Run a safe macOS-local smoke pass: macOS collect-plan, redacted live artifact counts, "
            "small triage benchmark, SQLite FTS benchmark, and external validation tool availability."
        ),
    )
    macos_live_smoke.add_argument("--output-dir", required=True, help="Directory for macOS smoke JSON/Markdown and benchmark outputs")
    macos_live_smoke.add_argument("--root", default="/", help="macOS evidence root for collect-plan (default: /)")
    macos_live_smoke.add_argument("--home", help="User home to inspect for redacted live artifacts (default: current home)")
    macos_live_smoke.add_argument("--case-db", help="Optional RapidTriage Case DB to include in large-case readiness profiling")
    macos_live_smoke.add_argument("--benchmark-file-count", type=int, default=DEFAULT_MACOS_SMOKE_BENCHMARK_FILES, help="Synthetic triage benchmark file count")
    macos_live_smoke.add_argument("--fts-record-count", type=int, default=DEFAULT_MACOS_SMOKE_FTS_RECORDS, help="Synthetic SQLite FTS benchmark row count")
    macos_live_smoke.add_argument("--keyword", default=DEFAULT_BENCHMARK_KEYWORD, help="Keyword used in synthetic benchmark checks")
    macos_live_smoke.add_argument("--include-path-details", action="store_true", help="Include raw local paths in smoke output; default stores hashes only")
    macos_live_smoke.add_argument("--overwrite", action="store_true", help="Allow replacing smoke files under OUTPUT_DIR")
    macos_live_smoke.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    columnar_benchmark = sub.add_parser(
        "columnar-benchmark",
        help="Benchmark ArtifactRecordV1 JSONL and optional Parquet columnar storage",
        description="Write synthetic ArtifactRecordV1 rows to JSONL and, when optional dependencies exist, Parquet",
    )
    columnar_benchmark.add_argument("--output-dir", required=True, help="Directory for columnar benchmark outputs")
    columnar_benchmark.add_argument("--record-count", type=int, default=10_000, help="Synthetic ArtifactRecordV1 row count")
    columnar_benchmark.add_argument("--keyword", default="PowerShell", help="Keyword embedded in every tenth synthetic row")
    columnar_benchmark.add_argument("--query-iterations", type=int, default=3, help="Repeated JSONL keyword scan samples")
    columnar_benchmark.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    columnar_convert = sub.add_parser(
        "columnar-convert",
        help="Convert ArtifactRecordV1 JSONL into optional Parquet columnar storage",
        description="Convert worker-parse ArtifactRecordV1 JSONL into row-grouped Parquet when pyarrow is installed",
    )
    columnar_convert.add_argument("--input-jsonl", required=True, help="ArtifactRecordV1 JSONL file from worker-parse")
    columnar_convert.add_argument("--output-parquet", required=True, help="Destination Parquet file")
    columnar_convert.add_argument("--row-group-size", type=int, default=100_000, help="Parquet row group size")
    columnar_convert.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    stress_plan = sub.add_parser(
        "stress-plan",
        help="Write a repeatable 1TB-10TB stress-test plan without generating large data",
        description="Create a stress-test runbook with resource caps, checkpoints, failure thresholds, and evidence requirements",
    )
    stress_plan.add_argument("--output-dir", required=True, help="Directory for stress plan outputs")
    stress_plan.add_argument("--size-tb", type=int, action="append", help="Evidence size scenario in TB (repeatable; default 1/5/10)")
    stress_plan.add_argument("--expected-throughput-mb-s", type=float, default=80.0, help="Expected ingest throughput for wall-clock estimates")
    stress_plan.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty stress-plan output directory")
    stress_plan.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    browser_stress = sub.add_parser(
        "browser-stress",
        help="Run optional Playwright large-result browser stress checks against a running web UI",
        description="Run Playwright browser checks for large-result DOM windowing, row-filter bounds, console errors, and latency budgets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage web --host 127.0.0.1 --port 8765
              rapidtriage browser-stress --base-url http://127.0.0.1:8765 --output-dir ./browser-qc --json
            """
        ),
    )
    browser_stress.add_argument("--base-url", default="http://127.0.0.1:8765", help="Running RapidTriage web UI base URL")
    browser_stress.add_argument("--output-dir", required=True, help="Directory for Playwright JSON/screenshot evidence")
    browser_stress.add_argument("--record-count", type=int, default=DEFAULT_BROWSER_STRESS_RECORD_COUNT, help="Synthetic record count requested from the large-result evidence endpoint")
    browser_stress.add_argument("--headed", action="store_true", help="Run Chromium headed instead of headless")
    browser_stress.add_argument("--require-playwright", action="store_true", help="Return non-zero if Playwright is unavailable")
    browser_stress.add_argument("--timeout-ms", type=int, default=30_000, help="Per-action Playwright timeout in milliseconds")
    browser_stress.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    sqlite_fts_benchmark = sub.add_parser(
        "sqlite-fts-benchmark",
        help="Run a deterministic synthetic SQLite FTS benchmark",
        description="Generate a synthetic SQLite FTS corpus and measure ingest, query latency, query plan hashes, and scale evidence",
    )
    sqlite_fts_benchmark.add_argument("--output-dir", required=True, help="Directory for benchmark database, JSON, and Markdown outputs")
    sqlite_fts_benchmark.add_argument("--record-count", type=int, default=SQLITE_FTS_DEFAULT_RECORD_COUNT, help="Synthetic row count, e.g. 100000 or 1000000")
    sqlite_fts_benchmark.add_argument("--keyword", default=DEFAULT_BENCHMARK_KEYWORD, help="Seeded keyword to query")
    sqlite_fts_benchmark.add_argument("--query-iterations", type=int, default=SQLITE_FTS_DEFAULT_QUERY_ITERATIONS, help="Repeated query samples for p50/p95 latency")
    sqlite_fts_benchmark.add_argument("--hit-every", type=int, default=SQLITE_FTS_DEFAULT_HIT_EVERY, help="Seed the keyword every N rows")
    sqlite_fts_benchmark.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty benchmark output directory")
    sqlite_fts_benchmark.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    large_case_readiness = sub.add_parser(
        "large-case-readiness",
        help="Combine Case DB and SQLite FTS evidence into a large-case readiness report",
        description="Assess Mac-local large-case search/indexing evidence before claiming 1TB/10TB or commercial-scale readiness",
    )
    large_case_readiness.add_argument("--case-db", help="Optional RapidTriage Case DB to profile")
    large_case_readiness.add_argument("--benchmark", action="append", default=[], help="SQLite FTS benchmark JSON; repeat for 100k/1M/10M runs")
    large_case_readiness.add_argument("--keyword", default=DEFAULT_BENCHMARK_KEYWORD, help="Representative keyword for the search backend contract")
    large_case_readiness.add_argument(
        "--max-query-p95-ms",
        type=float,
        default=DEFAULT_LARGE_CASE_P95_THRESHOLD_MS,
        help="Maximum accepted SQLite FTS benchmark query p95 in milliseconds",
    )
    large_case_readiness.add_argument(
        "--memory-cap-bytes",
        type=int,
        default=0,
        help="Optional memory cap to record in the #72 large-case readiness matrix",
    )
    large_case_readiness.add_argument("--output", help="Optional JSON output path")
    large_case_readiness.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    sqlite_wal_preview = sub.add_parser(
        "sqlite-wal-preview",
        help="Preview SQLite WAL sidecar frames and page hashes for recovery planning",
        description="Detect matching -wal/-shm files, parse WAL frame headers, and record page hashes without reconstructing rows",
    )
    sqlite_wal_preview.add_argument("database", help="Path to SQLite database")
    sqlite_wal_preview.add_argument("--output-dir", required=True, help="Directory for WAL preview JSON and Markdown outputs")
    sqlite_wal_preview.add_argument("--max-frames", type=int, default=20, help="Maximum WAL frames to preview")
    sqlite_wal_preview.add_argument("--preferred-trusted-tool", help="Preferred trusted comparison command, e.g. sqlite_dissect or xsqlite")
    sqlite_wal_preview.add_argument("--trusted-tool-timeout-seconds", type=int, default=300, help="Timeout for optional trusted SQLite recovery tool execution")
    sqlite_wal_preview.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    known_answer_qc = sub.add_parser(
        "known-answer-qc",
        help="Assess a known-answer corpus manifest and optional trusted manifest diff",
        description="Load a CFReDS/CFTT-style known-answer manifest, hash evidence paths, and compare against an optional trusted manifest",
    )
    known_answer_qc.add_argument("--manifest", required=True, help="RapidTriage known-answer manifest JSON")
    known_answer_qc.add_argument("--trusted-manifest", help="Optional trusted/reference known-answer manifest JSON")
    known_answer_qc.add_argument("--output-dir", required=True, help="Directory for QC JSON and Markdown outputs")
    known_answer_qc.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty QC output directory")
    known_answer_qc.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    validation.add_argument("--known-answer-manifest", help="Optional JSON manifest of NIST CFReDS/CFTT-style known-answer runs")
    validation.add_argument("--fixture-root", help="Repository/root path used to discover parser fixture corpus coverage")
    validation.add_argument("--independent-report", help="Optional independent validation report to hash and attach")
    validation.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    validation_diff_runners = sub.add_parser(
        "validation-diff-runners",
        help="Show trusted-tool runner matrix for QC items #76-#80",
        description="Build a machine-readable public corpus and trusted-tool diff runner matrix for EVTX, Registry, NTFS, and ESE validation",
    )
    validation_diff_runners.add_argument("--output", help="Optional JSON output path")
    validation_diff_runners.add_argument(
        "--search-path",
        action="append",
        default=[],
        help="Additional trusted-tool search path to prepend; repeat or separate directories with the OS path separator",
    )
    validation_diff_runners.add_argument(
        "--probe-versions",
        action="store_true",
        help="Run detected trusted-tool binaries with bounded version probes and capture output hashes",
    )
    validation_diff_runners.add_argument(
        "--version-timeout-seconds",
        type=float,
        default=VERSION_PROBE_TIMEOUT_SECONDS,
        help="Timeout per trusted-tool version probe when --probe-versions is set",
    )
    validation_diff_runners.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    final_qc_report = sub.add_parser(
        "final-qc-report",
        help="Build final QC execution report for items #81-#85",
        description="Generate the final QC wrapper report from validation package, runner matrix, performance runs, browser traces, reviewer signoff, and blocker ledger requirements",
    )
    final_qc_report.add_argument("--validation-package", help="Validation package JSON to hash into the final QC report")
    final_qc_report.add_argument("--runner-matrix", help="Validation diff runner matrix JSON to hash into the final QC report")
    final_qc_report.add_argument("--chain-of-custody", help="Chain-of-custody record/report path to hash into the final QC report")
    final_qc_report.add_argument("--audit-bundle", help="Audit hash chain or tamper-evident bundle path")
    final_qc_report.add_argument("--exhibit-bundle", help="Court exhibit bundle, manifest, or ZIP path")
    final_qc_report.add_argument("--performance-run", action="append", help="Performance run JSON/log path; repeatable")
    final_qc_report.add_argument("--browser-trace", action="append", help="Browser trace/screenshot artifact path; repeatable")
    final_qc_report.add_argument("--reviewer-signoff", action="append", help="Reviewer signoff document path; repeatable")
    final_qc_report.add_argument("--output", help="Optional final QC JSON output path")
    final_qc_report.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    commercial_readiness = sub.add_parser(
        "commercial-readiness",
        help="Summarize commercial parity gaps from the 120-item backlog",
        description="Build a commercial-readiness gate report so partial features cannot be advertised as AXIOM/WISDOM-class",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage commercial-readiness --json
              rapidtriage commercial-readiness --output-dir ./commercial-readiness --json
              rapidtriage commercial-readiness --validation-package ./validation/rapidtriage-validation-package.json --json
              rapidtriage commercial-readiness --validation-package ./validation/core-001-025.json --validation-package ./validation/core-026-030.json --json
              rapidtriage commercial-readiness --next-gate validated --limit 10
              rapidtriage commercial-readiness --next-gate validated --limit 5 --write-known-answer-template ./known-answer-runs.template.json
              rapidtriage commercial-readiness --template-items 1-120 --template-batch-size 5 --write-known-answer-template-dir ./known-answer-batches
              rapidtriage commercial-readiness --uplift-targets 70 --uplift-batch-size 5 --output-dir ./commercial-uplift
              rapidtriage commercial-readiness --strict
            """
        ),
    )
    commercial_readiness.add_argument("--backlog", help="Path to rapidtriage-commercial-parity-backlog.md")
    commercial_readiness.add_argument("--output-dir", help="Optional directory for JSON and Markdown gate reports")
    commercial_readiness.add_argument(
        "--validation-package",
        action="append",
        help="Optional validation package or known-answer manifest that maps passing datasets to backlog item numbers; repeat to combine batches",
    )
    commercial_readiness.add_argument(
        "--mac-first-evidence",
        action="append",
        help="Attach macos-live-smoke, large-case-readiness, email-external-parse JSON, or a QC directory containing those files as preparatory Mac evidence without satisfying commercial gates",
    )
    commercial_readiness.add_argument(
        "--next-gate",
        choices=MATURITY_GATE_ORDER,
        help="Focus console/JSON triage on items whose next required maturity gate matches this value",
    )
    commercial_readiness.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum priority items to show in the focused readiness plan (default: 25)",
    )
    commercial_readiness.add_argument(
        "--write-known-answer-template",
        help="Write a not-run known-answer manifest template for the selected next-gate priority items",
    )
    commercial_readiness.add_argument(
        "--write-known-answer-template-dir",
        help="Write not-run known-answer manifest templates in batches for --template-items",
    )
    commercial_readiness.add_argument(
        "--template-items",
        default="1-120",
        help="Item range/list for --write-known-answer-template-dir, e.g. 1-5,10,20-25 (default: 1-120)",
    )
    commercial_readiness.add_argument(
        "--template-batch-size",
        type=int,
        default=5,
        help="Number of backlog items per known-answer template batch (default: 5)",
    )
    commercial_readiness.add_argument(
        "--uplift-targets",
        type=int,
        default=70,
        help="Number of prioritized non-commercial goals to include in the commercial uplift plan (default: 70)",
    )
    commercial_readiness.add_argument(
        "--uplift-batch-size",
        type=int,
        default=5,
        help="Number of uplift goals per execution batch (default: 5)",
    )
    commercial_readiness.add_argument("--strict", action="store_true", help="Exit non-zero when commercial gaps remain")
    commercial_readiness.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_plan = sub.add_parser(
        "forensic-validation-plan",
        help="Build a focused validation execution plan for forensic items",
        description="Build a machine-readable execution plan for forensic validation items, defaulting to #1-#120",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage forensic-validation-plan --json
              rapidtriage forensic-validation-plan --items 1-120 --output-dir ./forensic-validation-plan
            """
        ),
    )
    forensic_validation_plan.add_argument(
        "--items",
        default=DEFAULT_FORENSIC_VALIDATION_ITEMS,
        help=f"Item range/list to include (default: {DEFAULT_FORENSIC_VALIDATION_ITEMS})",
    )
    forensic_validation_plan.add_argument("--output-dir", help="Optional directory for JSON and Markdown plan outputs")
    forensic_validation_plan.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_pack = sub.add_parser(
        "forensic-validation-pack",
        help="Create an executable evidence pack for a focused forensic validation batch",
        description="Create dataset templates, trusted-reference commands, and row-level diff contracts for a small validation batch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage forensic-validation-pack --items 1-5 --output-dir ./evtx-registry-pack --json
              rapidtriage forensic-validation-pack --items 12-13 --output-dir ./ntfs-pack
            """
        ),
    )
    forensic_validation_pack.add_argument(
        "--items",
        default=DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
        help=f"Item range/list to include (default: {DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS})",
    )
    forensic_validation_pack.add_argument("--output-dir", required=True, help="Directory for pack JSON, Markdown, dataset template, and command checklist")
    forensic_validation_pack.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_pack_assess = sub.add_parser(
        "forensic-validation-pack-assess",
        help="Assess whether a populated forensic validation pack is ready for validation gates",
        description="Check evidence path presence, SHA256 expectations, reviewer signoff, and row-level diff readiness for a validation pack",
    )
    forensic_validation_pack_assess.add_argument("--pack", required=True, help="Path to rapidtriage-forensic-validation-pack.json")
    forensic_validation_pack_assess.add_argument("--output", help="Optional JSON assessment output path")
    forensic_validation_pack_assess.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_batches = sub.add_parser(
        "forensic-validation-batches",
        help="Write five-item validation packs for a full forensic item range",
        description="Create plan output plus one executable validation pack per five-item batch, defaulting to #1-#120",
    )
    forensic_validation_batches.add_argument(
        "--items",
        default=DEFAULT_FORENSIC_VALIDATION_ITEMS,
        help=f"Item range/list to include (default: {DEFAULT_FORENSIC_VALIDATION_ITEMS})",
    )
    forensic_validation_batches.add_argument("--output-dir", required=True, help="Directory for the plan and batch pack folders")
    forensic_validation_batches.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_batches_assess = sub.add_parser(
        "forensic-validation-batches-assess",
        help="Assess all validation packs under a batch root directory",
        description="Assess every batch-*/rapidtriage-forensic-validation-pack.json under a validation batch root",
    )
    forensic_validation_batches_assess.add_argument("--root-dir", required=True, help="Directory created by forensic-validation-batches")
    forensic_validation_batches_assess.add_argument("--output", help="Optional JSON assessment output path")
    forensic_validation_batches_assess.add_argument(
        "--strict-external",
        action="store_true",
        help="Exit non-zero unless every dataset is backed by non-smoke external validation evidence",
    )
    forensic_validation_batches_assess.add_argument(
        "--strict-commercial",
        action="store_true",
        help="Exit non-zero unless every dataset is commercial-grade ready",
    )
    forensic_validation_batches_assess.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_smoke_populate = sub.add_parser(
        "forensic-validation-smoke-populate",
        help="Populate validation batches with deterministic internal smoke evidence",
        description="Fill every generated validation pack dataset with synthetic evidence and clean internal diff output for plumbing verification",
    )
    forensic_validation_smoke_populate.add_argument("--root-dir", required=True, help="Directory created by forensic-validation-batches")
    forensic_validation_smoke_populate.add_argument("--output", help="Optional JSON smoke manifest output path")
    forensic_validation_smoke_populate.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    forensic_validation_evidence_import = sub.add_parser(
        "forensic-validation-evidence-import",
        help="Import external validation evidence paths into generated validation batches",
        description="Apply a manifest of source/RapidTriage/reference/diff/signoff paths to validation packs and rerun aggregate assessment",
    )
    forensic_validation_evidence_import.add_argument("--root-dir", required=True, help="Directory created by forensic-validation-batches")
    forensic_validation_evidence_import.add_argument("--manifest", required=True, help="JSON manifest with datasets and evidence paths")
    forensic_validation_evidence_import.add_argument("--output", help="Optional JSON import manifest output path")
    forensic_validation_evidence_import.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    cross_tool = sub.add_parser(
        "cross-tool-validate",
        help="Compare RapidTriage output against external forensic tool exports",
        description="Build a cross-tool validation report for detecting parser omissions and schema mismatches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage cross-tool-validate --rapid-output rapidtriage-artifacts-eventlog.json --reference-output evtxecmd=Security.csv --json
              rapidtriage cross-tool-validate --rapid-output rapidtriage-filesystem.json --reference-output mftecmd=MFTECmd.csv --min-overlap 0.9 --output cross-tool.json
            """
        ),
    )
    cross_tool.add_argument("--rapid-output", required=True, help="RapidTriage JSON/JSONL/CSV output to compare")
    cross_tool.add_argument(
        "--reference-output",
        action="append",
        required=True,
        help="External tool output as NAME=PATH; repeat for EvtxECmd, RECmd, MFTECmd, PECmd, Plaso, etc.",
    )
    cross_tool.add_argument("--min-overlap", type=float, default=0.8, help="Minimum reference-key overlap ratio")
    cross_tool.add_argument(
        "--backlog-item",
        action="append",
        type=int,
        help="Commercial-readiness backlog item number satisfied by a passing comparison; repeat for #1-#5 evidence",
    )
    cross_tool.add_argument(
        "--tool-version",
        action="append",
        help="External tool version metadata as NAME=VERSION; repeat for EvtxECmd, RECmd, RegistryExplorer, etc.",
    )
    cross_tool.add_argument(
        "--tool-command",
        action="append",
        help="External tool command/provenance as NAME=COMMAND; repeat for each reference export.",
    )
    cross_tool.add_argument(
        "--source-evidence",
        action="append",
        help="Original evidence file used to produce the compared outputs; repeat to hash multiple sources.",
    )
    cross_tool.add_argument(
        "--independent-report",
        action="append",
        help="Independent reviewer report/sign-off file to hash into the validation report.",
    )
    cross_tool.add_argument(
        "--corpus-scope",
        default="",
        help="Short corpus scope statement, e.g. NIST CFReDS Security.evtx plus local deleted-record fixture.",
    )
    cross_tool.add_argument("--output", help="Optional JSON report path")
    cross_tool.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    image_workflow_validate = sub.add_parser(
        "image-workflow-validate",
        help="Diff E01/RAW/virtual-disk/container workflow metadata against trusted exports",
        description=(
            "Build the #22-#25 image workflow trusted-diff artifact used before report-grade "
            "claims for E01/Ex01, RAW/split, VHD/VHDX/VMDK/VDI/QCOW, and vendor/export-first containers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage image-workflow-validate --item-number 22 --rapid-output rapidtriage-e01.json --trusted-output ewfverify.csv --trusted-tool ewfverify --json
              rapidtriage image-workflow-validate --item-number 24 --rapid-output rapidtriage-virtual-disk.json --trusted-output qemu-reference.json --trusted-tool qemu-img --output image-diff.json
            """
        ),
    )
    image_workflow_validate.add_argument(
        "--item-number",
        type=int,
        choices=(22, 23, 24, 25),
        required=True,
        help="Commercial-readiness image workflow item: 22=E01/Ex01, 23=RAW/split, 24=virtual disk, 25=AD1/L01/AFF/XVA export workflow",
    )
    image_workflow_validate.add_argument("--rapid-output", required=True, help="RapidTriage image workflow JSON/JSONL/CSV output")
    image_workflow_validate.add_argument("--trusted-output", required=True, help="Trusted tool/vendor workflow JSON/JSONL/CSV output")
    image_workflow_validate.add_argument(
        "--trusted-tool",
        required=True,
        help="Trusted tool or workflow name, e.g. ewfverify, tsk_recover, qemu-img, FTK Imager, vendor export manifest",
    )
    image_workflow_validate.add_argument("--output", help="Optional JSON trusted-diff path")
    image_workflow_validate.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    usn_state_template = sub.add_parser(
        "usn-state-replay-template",
        help="Write a known-answer CSV template for USN state replay validation",
        description="Write a USN create/rename/delete state replay known-answer CSV and manifest for cross-tool validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage usn-state-replay-template --output ./usn-state-replay-known-answer.csv
              rapidtriage usn-state-replay-template --output ./usn-state-replay-known-answer.csv --empty --json
            """
        ),
    )
    usn_state_template.add_argument("--output", required=True, help="CSV template output path")
    usn_state_template.add_argument("--empty", action="store_true", help="Write headers only, without example rows")
    usn_state_template.add_argument("--json", action="store_true", help="Print machine-readable manifest JSON")

    run_attach_validation_diff = sub.add_parser(
        "run-attach-validation-diff",
        help="Attach trusted-tool validation diff JSON files to a completed run",
        description=(
            "Copy trusted-tool/cross-tool validation diff outputs into a completed run directory "
            "and register them in rapidtriage-run-summary.json for API/UI validation-package review."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage run-attach-validation-diff ./rapidtriage-run --diff-output usn_state=./usn-state-cross-tool.json
              rapidtriage run-attach-validation-diff ./rapidtriage-run/rapidtriage-run-summary.json --diff-output evtx=./evtx-cross-tool.json --overwrite --json
            """
        ),
    )
    run_attach_validation_diff.add_argument(
        "run_output",
        help="Completed run output directory or rapidtriage-run-summary.json",
    )
    run_attach_validation_diff.add_argument(
        "--diff-output",
        action="append",
        required=True,
        help="Validation diff output as NAME=PATH; repeat for EVTX, Registry, MFT, USN, etc.",
    )
    run_attach_validation_diff.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing attached validation diff with the same NAME",
    )
    run_attach_validation_diff.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    confidence_dashboard = sub.add_parser(
        "confidence-dashboard",
        help="Summarize report-grade, validation-required, triage, and unsupported result counts",
        description="Build an evidence confidence dashboard from a completed run",
    )
    confidence_dashboard.add_argument("run_output", help="Completed run output directory or rapidtriage-run-summary.json")
    confidence_dashboard.add_argument("--output", help="Optional JSON output path")
    confidence_dashboard.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    parser_explainability = sub.add_parser(
        "parser-explainability",
        help="Export parser/source/provenance explanations for run records",
        description="Build a parser explainability report for source path, parser version, hashes, offsets, and validation state",
    )
    parser_explainability.add_argument("run_output", help="Completed run output directory or rapidtriage-run-summary.json")
    parser_explainability.add_argument("--output", help="Optional JSON output path")
    parser_explainability.add_argument("--markdown-output", help="Optional Markdown output path")
    parser_explainability.add_argument("--limit", type=int, default=500, help="Maximum records to include")
    parser_explainability.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    reproducibility = sub.add_parser(
        "reproducibility-kit",
        help="Compare two completed runs for same-input/same-output reproducibility",
        description="Build a reproducibility kit with canonical output hashes and per-output diffs",
    )
    reproducibility.add_argument("--baseline-run", required=True, help="Baseline run directory or summary JSON")
    reproducibility.add_argument("--candidate-run", required=True, help="Candidate run directory or summary JSON")
    reproducibility.add_argument("--output-dir", required=True, help="Directory for reproducibility JSON/Markdown outputs")
    reproducibility.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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

    keyword_packs = sub.add_parser(
        "keyword-packs",
        help="List built-in keyword packs for repeatable searches",
        description="List built-in keyword packs for credentials, execution, network, browser/AI, and Windows IR review",
    )
    keyword_packs.add_argument("--json", action="store_true", help="Print machine-readable JSON")

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
    run.add_argument("--max-file-count", type=int, default=0, help="Cap run docs/files candidates and copied files per extract stage (0 means unlimited)")
    run.add_argument("--memory-cap-bytes", type=int, default=0, help="Stop the run at safe stage boundaries if RSS exceeds this value (0 also honors RAPIDTRIAGE_MEMORY_CAP_BYTES when set)")
    run.add_argument("--e01-partition-start-sector", type=int, help="Use this mmls partition start sector for direct E01/Ex01 recovery instead of the automatic recommendation")
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
        "--columnar-store",
        action="store_true",
        help="Write an opt-in columnar sidecar: stage ArtifactRecordV1 rows as JSONL and convert to Parquet for large-case query (requires pyarrow from the columnar extra; skipped when unavailable)",
    )
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
              rapidtriage web --remote --host 0.0.0.0 --token <token>
            """
        ),
    )
    add_web_arguments(web)
    return parser

__all__ = [
    "DOCS_EPILOG",
    "EXTRACT_EPILOG",
    "FILES_EPILOG",
    "HELP_FORMATTER",
    "MANIFEST_EPILOG",
    "TOP_LEVEL_EPILOG",
    "build_parser",
]
