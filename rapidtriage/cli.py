from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import textwrap
from pathlib import Path

from .core.audit import audit_path_for, write_audit_record
from .core.backup import BackupError, build_case_backup, restore_case_backup
from .core.artifacts import ArtifactCollectionError, SUPPORTED_ARTIFACT_KINDS, run_artifact_collection
from .artifacts.email_external import EmailExternalParserError, run_email_external_parse
from .core.artifact_taxonomy import build_taxonomy_audit
from .core.benchmark import (
    DEFAULT_BENCHMARK_FILE_COUNT,
    DEFAULT_BENCHMARK_KEYWORD,
    BenchmarkError,
    build_stress_test_plan,
    run_benchmark,
)
from .core.browser_stress import DEFAULT_BROWSER_STRESS_RECORD_COUNT, run_browser_large_result_stress
from .core.benchmark_fts import (
    SQLITE_FTS_DEFAULT_HIT_EVERY,
    SQLITE_FTS_DEFAULT_QUERY_ITERATIONS,
    SQLITE_FTS_DEFAULT_RECORD_COUNT,
    SqliteFtsBenchmarkError,
    run_sqlite_fts_benchmark,
)
from .core.bundle import BundleError, build_submission_bundle
from .core.carving import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_CARVE_BYTES,
    DEFAULT_MAX_SCAN_BYTES,
    CarvingError,
    run_bounded_carving,
)
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
from .core.commercial_readiness import (
    MATURITY_GATE_ORDER,
    CommercialReadinessError,
    build_known_answer_template_batches,
    build_known_answer_manifest_template,
    build_commercial_readiness_report,
    parse_item_range,
    write_known_answer_template_batches,
    write_known_answer_manifest_template,
)
from .core.cloud_api import (
    DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
    DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
    DEFAULT_CLOUD_BEARER_TOKEN_ENV,
    CloudApiCollectionError,
    run_cloud_api_collection,
)
from .core.columnar_store import ColumnarStoreUnavailable, convert_jsonl_to_parquet, run_columnar_benchmark
from .core.compare import CompareError, compare_many_paths, compare_paths
from .core.confidence import (
    ConfidenceDashboardError,
    build_confidence_dashboard,
    build_parser_explainability,
    build_reproducibility_kit,
)
from .core.cross_tool import (
    CrossToolValidationError,
    build_cross_tool_validation_report,
    write_usn_state_replay_known_answer_template,
)
from .core.docs import build_manifest, run_docs_search, write_result
from .core.doctor import format_doctor_text, run_doctor
from .core.enterprise import build_enterprise_policy
from .core.evidence import identify_evidence
from .core.e01 import build_windows11_e01_known_answer_manifest
from .core.e01_hash import E01StreamingHashError, run_e01_streaming_hash
from .core.e01_smoke import run_windows11_e01_smoke
from .core.extract import DEFAULT_EXTRACT_MANIFEST_NAME, ExtractError, SUPPORTED_DOC_KINDS, run_extract
from .core.files import ALL_FILE_CATEGORIES, FileScanError, run_files_scan
from .core.indicators import IndicatorSummaryError, build_indicator_summary
from .core.input_root import SUPPORTED_INPUT_ROOT_KINDS, resolve_input_root
from .core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from .core.known_answer_qc import run_known_answer_qc
from .core.macos_live_smoke import (
    DEFAULT_MACOS_SMOKE_BENCHMARK_FILES,
    DEFAULT_MACOS_SMOKE_FTS_RECORDS,
    MacOsLiveSmokeError,
    run_macos_live_smoke,
)
from .core.kakaotalk import (
    DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
    DEFAULT_MEMORY_SQLITE_MAX_HITS,
    DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
    DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT,
    KakaoTalkDecryptError,
    run_kakaotalk_windows_collect,
    run_kakaotalk_decrypt,
    run_kakaotalk_key_store_inspect,
    run_kakaotalk_memory_carve,
    run_kakaotalk_sqlcipher_probe,
    run_kakaotalk_userdir_bruteforce,
)
from .artifacts.kakaotalk_macos import (
    DEFAULT_MACOS_REPORT_MAX_MESSAGES,
    KakaoTalkMacOsReportError,
    run_kakaotalk_macos_report,
)
from .core.normalize import NormalizationError, build_normalized_case
from .core.ocr_queue import OcrQueueError, build_ocr_queue
from .core.plugins import PluginError, load_plugin_registry, validate_plugin_manifest, read_plugin_manifest
from .core.rearchitecture import build_rearchitecture_status
from .core.rules import RuleConfigError, load_rule_set
from .core.run import RunModeError, SUPPORTED_RUN_MODES, run_triage_mode
from .core.run_validation import RunValidationAttachmentError, attach_validation_diff_outputs
from .core.sample_case import DEFAULT_SAMPLE_DIR, DEFAULT_SAMPLE_MODE, SampleCaseError, create_sample_case, run_sample_workflow
from .core.search import SearchError, run_unified_search
from .core.source_reader import SourceReadError, render_source_read_text, run_source_read
from .core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from .core.timeline import TimelineError, build_timeline_report, run_timeline
from .core.timeline_export import TimelineExportError, build_unified_timeline_export
from .core.validation import ValidationError, build_validation_package
from .core.validation_diff_runners import (
    VERSION_PROBE_TIMEOUT_SECONDS,
    build_tool_search_path,
    build_validation_diff_runner_matrix,
    write_validation_diff_runner_matrix,
)
from .core.validation_final_qc import build_final_qc_execution_report, write_final_qc_execution_report
from .core.vsc import VscCompareError, compare_vsc_snapshots, discover_vsc_snapshot_roots, extract_vsc_changes
from .core.worker import RustWorkerClient, WorkerError
from .core.forensic_validation_plan import (
    DEFAULT_FORENSIC_VALIDATION_ITEMS,
    DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
    assess_forensic_validation_batches,
    assess_forensic_validation_pack,
    build_forensic_validation_pack,
    build_forensic_validation_plan,
    import_forensic_validation_evidence_manifest,
    populate_forensic_validation_smoke_fixtures,
    write_forensic_validation_batches,
    write_forensic_validation_pack,
    write_forensic_validation_plan,
)

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
    parser.add_argument("--crash-log-dir", help="Local-only directory for web/API crash reports")


def parse_named_cli_values(
    values: list[str],
    *,
    option_name: str,
    parser: argparse.ArgumentParser,
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            parser.error(f"{option_name} must use NAME=VALUE")
        name, raw = value.split("=", 1)
        if not name.strip() or not raw.strip():
            parser.error(f"{option_name} must use NAME=VALUE")
        parsed[name.strip()] = raw.strip()
    return parsed


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
    case_review.add_argument("--reviewer", help="Reviewer name")
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
        help="Optional validation package or known-answer manifest that maps passing datasets to backlog item numbers",
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
        description="Build a machine-readable execution plan for forensic validation items, defaulting to #1-#65",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage forensic-validation-plan --json
              rapidtriage forensic-validation-plan --items 1-65 --output-dir ./forensic-validation-plan
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
        description="Create plan output plus one executable validation pack per five-item batch, defaulting to #1-#65",
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
    run.add_argument("--max-file-count", type=int, default=0, help="Cap copied files per extract stage (0 means unlimited)")
    run.add_argument("--memory-cap-bytes", type=int, default=0, help="Stop the run at safe stage boundaries if RSS exceeds this value (0 also honors RAPIDTRIAGE_MEMORY_CAP_BYTES when set)")
    run.add_argument("--e01-partition-start-sector", type=int, help="Use this mmls partition start sector for direct E01/Ex01 recovery instead of the automatic recommendation")
    run.add_argument("--overwrite", action="store_true", help="Allow extract stages to overwrite existing output files")
    run.add_argument("--resume", action="store_true", help="Reuse valid existing stage JSON outputs in OUTPUT_DIR and rerun missing or invalid stages")
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


def run_web_server(
    host: str,
    port: int,
    reload: bool = False,
    auth_token: str | None = None,
    allow_remote_without_auth: bool = False,
    crash_log_dir: str | None = None,
) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"} and not auth_token and not allow_remote_without_auth:
        raise RuntimeError(
            "Refusing to bind RapidTriage to a non-localhost interface without --auth-token. "
            "Use --auth-token or --allow-remote-without-auth if you understand the risk."
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("rapidtriage web requires the 'web' extra: pip install 'dashcam-tools[web]'") from exc
    print(f"Starting rapidtriage web UI at http://{host}:{port}")
    if auth_token:
        import os

        os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = auth_token
    if crash_log_dir:
        import os

        os.environ["RAPIDTRIAGE_CRASH_LOG_DIR"] = str(Path(crash_log_dir).expanduser().resolve())
    uvicorn.run("rapidtriage.api.app:app", host=host, port=port, reload=reload)
    return 0


def web_main(argv=None) -> int:
    parser = build_web_parser()
    args = parser.parse_args(argv)
    try:
        return run_web_server(
            args.host,
            args.port,
            args.reload,
            args.auth_token,
            args.allow_remote_without_auth,
            args.crash_log_dir,
        )
    except RuntimeError as exc:
        parser.error(str(exc))
    return 2


def write_kakaotalk_message_residue_csv(payload: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = payload.get("chat_message_residues") or []
    fieldnames = [
        "source_path",
        "source_offset",
        "chat_id",
        "log_id",
        "author_id",
        "send_at",
        "send_at_utc",
        "type",
        "deleted",
        "message_text",
        "message_text_length",
        "message_text_sha256",
        "attachment_length",
        "attachment_sha256",
    ]
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                writer.writerow(row)


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

    if args.command == "cloud-collect":
        manifest_path = Path(args.manifest).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = run_cloud_api_collection(
                manifest_path,
                output_dir=output_dir,
                bearer_token_env=args.bearer_token_env,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.max_response_bytes,
                allow_insecure_http=args.allow_insecure_http,
                dry_run=args.dry_run,
            )
        except CloudApiCollectionError as exc:
            parser.error(str(exc))
        output = Path(str(payload["output"]))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="cloud-collect",
            options={
                "output_dir": str(output_dir),
                "bearer_token_env": args.bearer_token_env,
                "timeout_seconds": args.timeout_seconds,
                "max_response_bytes": args.max_response_bytes,
                "allow_insecure_http": args.allow_insecure_http,
                "dry_run": args.dry_run,
            },
            input_files=[("cloud-api-manifest", manifest_path)],
            output_files=[("cloud-collect-json", output)],
        )
        print(f"Saved cloud collection JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(
            f"Requests: {payload['summary']['request_count']}  "
            f"Collected: {payload['summary']['collected_count']}  Errors: {payload['summary']['error_count']}"
        )
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
            return run_web_server(
                args.host,
                args.port,
                args.reload,
                args.auth_token,
                args.allow_remote_without_auth,
                args.crash_log_dir,
            )
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

    if args.command == "enterprise-policy":
        payload = build_enterprise_policy()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage enterprise policy")
            print(f"Telemetry enabled: {payload['telemetry']['enabled']}")
            print(f"License required: {payload['license_activation']['required']}")
            print(f"RBAC status: {payload['rbac']['status']}")
            print(f"Multi-user server: {payload['multi_user_case_server']['status']}")
        return 0

    if args.command == "rearchitecture-status":
        payload = build_rearchitecture_status()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage re-architecture status")
            print(f"Overall: {payload['overall_status']}")
            print(f"Checks: {payload['passed_count']}/{payload['check_count']} passed")
            focus = payload.get("focus_balance") if isinstance(payload.get("focus_balance"), dict) else {}
            if focus:
                print(f"Focus lanes: {focus.get('lane_count')} ({', '.join(sorted(focus.get('lanes', {}).keys()))})")
            if payload["blocked_count"]:
                print(f"Blocked checks: {payload['blocked_count']}")
            plan_items = payload.get("balanced_next_stage_plan")
            if isinstance(plan_items, list) and plan_items:
                print("Balanced 1-18 plan:")
                for item in plan_items:
                    if not isinstance(item, dict):
                        continue
                    print(
                        f"- {item.get('number')}. {item.get('title')} "
                        f"[{item.get('lane')}, {item.get('status')}]"
                    )
            print("Next steps:")
            for item in payload["next_steps"]:
                print(f"- {item}")
        return 0

    if args.command == "worker-parse":
        env_worker = os.environ.get("RAPIDTRIAGE_RUST_WORKER") or ""
        client = (
            RustWorkerClient(executable=Path(args.worker).expanduser().resolve(), timeout_seconds=args.timeout_seconds)
            if args.worker
            else RustWorkerClient(
                executable=Path(env_worker).expanduser().resolve() if env_worker else None,
                timeout_seconds=args.timeout_seconds,
            )
        )
        try:
            payload = client.parse_to_jsonl(
                kind=args.kind,
                source=Path(args.source).expanduser().resolve(),
                output_path=Path(args.output).expanduser().resolve(),
                case_id=args.case_id,
                source_id=args.source_id,
                extra_args=args.extra_arg or (),
            )
        except (WorkerError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Worker pipeline: {payload['pipeline_status']}")
            print(f"Records: {payload['artifact_store']['record_count']}")
            print(f"Output: {payload['artifact_store']['path']}")
        return 0

    if args.command == "case-backup":
        try:
            payload = build_case_backup(
                database_path=Path(args.database).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (BackupError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved case backup manifest: {Path(args.output_dir).expanduser().resolve() / 'rapidtriage-case-backup-manifest.json'}")
            print(f"Copied files: {payload['copied_count']}")
        return 0

    if args.command == "case-restore":
        try:
            payload = restore_case_backup(
                manifest_path=Path(args.manifest).expanduser().resolve(),
                output_path=Path(args.output).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (BackupError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Restored case database: {payload['restored_database']}")
            print(f"Hash verified: {payload['hash_verified']}")
        return 0

    if args.command == "case-acquisition":
        database = open_case_database(Path(args.database).expanduser().resolve())
        try:
            if args.list:
                records = database.list_acquisition_metadata(args.case_id)
                payload = {
                    "command": "case-acquisition",
                    "database": str(database.path),
                    "case_id": args.case_id,
                    "records": records,
                    "record_count": len(records),
                }
            else:
                record = database.record_acquisition_metadata(
                    case_id=args.case_id,
                    evidence_source_citation_id=args.evidence_source_citation_id,
                    operator=args.operator,
                    acquisition_started_at=args.started_at,
                    acquisition_completed_at=args.completed_at,
                    source_identifier=args.source_identifier,
                    write_blocker=args.write_blocker,
                    acquisition_tool=args.tool,
                    acquisition_tool_version=args.tool_version,
                    whole_source_sha256=args.whole_source_sha256,
                    notes=args.notes,
                )
                payload = {
                    "command": "case-acquisition",
                    "database": str(database.path),
                    "case_id": args.case_id,
                    "record": record,
                }
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        elif args.list:
            print(f"Acquisition metadata records: {payload['record_count']}")
            for record in payload["records"]:
                print(f"- {record['citation_id']} source={record['source_identifier']} operator={record['operator']}")
        else:
            record = payload["record"]
            print(f"Recorded acquisition metadata: {record['citation_id']}")
            if record.get("whole_source_sha256"):
                print(f"Whole-source SHA256: {record['whole_source_sha256']}")
        return 0

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
                print(f"Saved training lab manifest: {run_payload['training_lab_manifest']}")
        return 0

    if args.command == "case-db":
        database_path = Path(args.database).expanduser().resolve()
        try:
            database = open_case_database(database_path)
            init_payload = database.initialize()
            created_case = None
            imported_run = None
            imported_vsc_compare = None
            imported_worker_jsonl = None
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
            if args.import_vsc_compare:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-vsc-compare")
                imported_vsc_compare = database.import_vsc_compare(
                    Path(args.import_vsc_compare).expanduser().resolve(),
                    case_id=import_case_id,
                    case_name=args.name,
                )
            if args.import_worker_jsonl:
                import_case_id = args.case_id or args.create_case
                if not import_case_id:
                    parser.error("--case-id or --create-case is required with --import-worker-jsonl")
                imported_worker_jsonl = database.import_worker_jsonl(
                    Path(args.import_worker_jsonl).expanduser().resolve(),
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
            "imported_vsc_compare": imported_vsc_compare,
            "imported_worker_jsonl": imported_worker_jsonl,
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
            if imported_vsc_compare:
                print(f"Imported VSC compare into case: {imported_vsc_compare['case_id']}")
                print(f"VSC import counts: {imported_vsc_compare['summary']}")
            if imported_worker_jsonl:
                print(f"Imported worker JSONL into case: {imported_worker_jsonl['case_id']}")
                print(f"Worker import counts: {imported_worker_jsonl['summary']}")
            if cases:
                print(f"Cases: {len(cases)}")
                for case in cases:
                    print(f"- {case.case_id}: {case.name}")
        return 0

    if args.command == "case-search":
        database_path = Path(args.database).expanduser().resolve()
        try:
            resolved_keywords = resolve_keyword_packs(
                args.keyword,
                pack_names=args.keyword_pack,
                pack_files=[Path(path) for path in (args.keyword_pack_file or [])],
            )
        except KeywordPackError as exc:
            parser.error(str(exc))
        try:
            database = open_case_database(database_path)
            payload = database.search_case(
                case_id=args.case_id,
                keywords=resolved_keywords,
                limit=args.limit,
                sources=args.source,
                metadata_filters=args.metadata,
                review_status=args.review_status,
                verification_status=args.verification_status,
            )
            if args.save_as:
                payload["saved_search"] = database.save_search(
                    case_id=args.case_id,
                    name=args.save_as,
                    keywords=resolved_keywords,
                    limit=args.limit,
                    sources=args.source,
                    metadata_filters=args.metadata,
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
                assignee=args.assignee,
                priority=args.priority,
                due_at=args.due_at,
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

    if args.command == "case-db-report":
        try:
            database = open_case_database(Path(args.database).expanduser().resolve())
            payload = database.export_reviewed_items(
                case_id=args.case_id,
                include_all=args.include_all,
                max_items=args.max_items,
            )
        except CaseDatabaseError as exc:
            parser.error(str(exc))
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json or args.output:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Case DB report candidates: {payload['summary']['exported_item_count']}")
            for item in payload["items"]:
                print(
                    f"- {item['review_citation_id']} -> {item['target_citation_id']} "
                    f"[{item['source']}] {item.get('title') or item.get('path')}"
                )
        return 0

    if args.command == "evidence":
        payload = identify_evidence(Path(args.source)).to_dict()
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Adapter: {payload['adapter']}")
            print(f"Format: {payload['detected_format']}")
            print(f"Supported now: {payload['supported']}")
            print(f"Support level: {payload.get('support_level', '')}")
            print(f"Scan strategy: {payload.get('scan_strategy', '')}")
            print(f"Message: {payload['message']}")
            if payload["missing_tools"]:
                print(f"Missing tools: {', '.join(payload['missing_tools'])}")
            next_actions = payload.get("next_actions") if isinstance(payload.get("next_actions"), list) else []
            if next_actions:
                print("Next actions:")
                for action in next_actions:
                    print(f"- {action}")
            warnings = payload.get("warnings") if isinstance(payload.get("warnings"), list) else []
            if warnings:
                print("Warnings:")
                for warning in warnings:
                    print(f"- {warning}")
            if args.output:
                print(f"Saved: {Path(args.output).expanduser().resolve()}")
            runbook = payload.get("ingest_workflow", {}).get("operator_runbook") if isinstance(payload.get("ingest_workflow"), dict) else None
            if isinstance(runbook, dict):
                commands = runbook.get("recommended_commands") if isinstance(runbook.get("recommended_commands"), dict) else {}
                if commands:
                    print("Recommended commands:")
                    for name, command in commands.items():
                        print(f"- {name}: {command}")
        return 0

    if args.command == "e01-known-answer":
        payload = build_windows11_e01_known_answer_manifest(
            Path(args.source),
            case_id=args.case_id,
            expected_partition_start_sector=args.expected_partition_start_sector,
            expected_artifacts=args.expected_artifact,
            validation_commands=args.validation_command,
        )
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"E01 known-answer manifest: {payload['case_id']}")
            print(f"Status: {payload['status']}")
            print(f"Source: {payload['source_image']['path']}")
            if args.output:
                print(f"Saved: {Path(args.output).expanduser().resolve()}")
            print(f"Manifest SHA256: {payload['manifest_sha256']}")
            print("Next steps:")
            for action in payload["operator_next_steps"]:
                print(f"- {action}")
        return 0

    if args.command == "e01-smoke":
        payload = run_windows11_e01_smoke(
            Path(args.source),
            output_dir=Path(args.output_dir),
            case_id=args.case_id,
            mode=args.mode,
            input_kind=args.input_kind,
            expected_partition_start_sector=args.expected_partition_start_sector,
            expected_artifacts=args.expected_artifact,
            validation_commands=args.validation_command,
            execute=not args.plan_only,
            read_only=not args.write_extracts,
            resume=args.resume,
            max_file_count=args.max_file_count,
            max_extract_size_bytes=args.max_extract_size_bytes,
            memory_cap_bytes=args.memory_cap_bytes,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"E01 smoke report: {payload['case_id']}")
            print(f"Status: {payload['status']}")
            print(f"Source: {payload['source_path']}")
            print(f"Saved: {payload['outputs']['smoke_report']['path']}")
            print("Stages:")
            for stage in payload["stages"]:
                print(f"- {stage['id']}: {stage['status']}")
            run_error = payload.get("run_error")
            if isinstance(run_error, dict) and run_error.get("failure_guidance"):
                guidance = run_error["failure_guidance"]
                print(f"Run blocker: {guidance.get('title', run_error.get('error'))}")
                for action in guidance.get("next_actions", []):
                    print(f"- {action}")
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
                resume=args.resume,
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

    if args.command == "macos-live-smoke":
        try:
            payload = run_macos_live_smoke(
                output_dir=Path(args.output_dir),
                root=Path(args.root),
                home=Path(args.home) if args.home else None,
                benchmark_file_count=args.benchmark_file_count,
                fts_record_count=args.fts_record_count,
                keyword=args.keyword,
                overwrite=args.overwrite,
                include_path_details=args.include_path_details,
            )
        except (MacOsLiveSmokeError, BenchmarkError, SearchError, RunModeError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload.get("summary", {})
            print(f"Saved macOS live smoke JSON: {payload['outputs']['json']}")
            print(f"Saved macOS live smoke report: {payload['outputs']['markdown']}")
            print(
                f"Local smoke score: {summary.get('local_smoke_score')} "
                f"({summary.get('passed_count')}/{summary.get('check_count')} checks)"
            )
        return 0

    if args.command == "e01-hash":
        try:
            payload = run_e01_streaming_hash(
                source_path=Path(args.source).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                algorithms=tuple(args.algorithm or ["sha256", "sha1", "md5"]),
                chunk_size=args.chunk_size,
                checkpoint_interval_bytes=args.checkpoint_interval_bytes,
                overwrite=args.overwrite,
            )
        except (E01StreamingHashError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved E01 hash JSON: {payload['outputs']['json']}")
            print(f"Saved E01 hash report: {payload['outputs']['markdown']}")
            print(f"SHA256: {payload['digests'].get('sha256', '')}")
        return 0

    if args.command == "columnar-benchmark":
        try:
            payload = run_columnar_benchmark(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                record_count=args.record_count,
                keyword=args.keyword,
                query_iterations=args.query_iterations,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            jsonl = payload["jsonl_baseline"]
            parquet = payload["parquet"]
            print(f"Saved columnar benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved columnar benchmark report: {payload['outputs']['markdown']}")
            print(
                "JSONL: "
                f"{jsonl['record_count']} rows in {jsonl['seconds']}s "
                f"({jsonl['records_per_second']} rows/s), query p95 {jsonl['query_seconds_p95']}s"
            )
            print(f"Parquet: {parquet['status']}")
            print(f"DuckDB Parquet query: {payload['duckdb_parquet_query']['status']}")
        return 0

    if args.command == "columnar-convert":
        try:
            payload = convert_jsonl_to_parquet(
                input_jsonl=Path(args.input_jsonl).expanduser().resolve(),
                output_parquet=Path(args.output_parquet).expanduser().resolve(),
                row_group_size=args.row_group_size,
            )
        except (ColumnarStoreUnavailable, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved Parquet: {payload['output_parquet']}")
            print(f"Saved conversion manifest: {payload['manifest_path']}")
            print(
                "Rows: "
                f"{payload['record_count']}  Rejected: {payload['rejected_count']}  "
                f"Rows/s: {payload['records_per_second']}"
            )
        return 0

    if args.command == "stress-plan":
        try:
            payload = build_stress_test_plan(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                evidence_sizes_tb=tuple(args.size_tb or [1, 5, 10]),
                expected_throughput_mb_s=args.expected_throughput_mb_s,
                overwrite=args.overwrite,
            )
        except (BenchmarkError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved stress plan JSON: {payload['outputs']['json']}")
            print(f"Saved stress plan report: {payload['outputs']['markdown']}")
            print(f"Scenarios: {payload['summary']['scenario_count']}")
        return 0

    if args.command == "browser-stress":
        payload = run_browser_large_result_stress(
            base_url=args.base_url,
            output_dir=Path(args.output_dir).expanduser().resolve(),
            record_count=args.record_count,
            headless=not args.headed,
            require_playwright=args.require_playwright,
            timeout_ms=args.timeout_ms,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved browser stress JSON: {Path(args.output_dir).expanduser().resolve() / 'browser-large-result-stress.json'}")
            print(f"Status: {payload['status']}")
            if payload.get("skip_reason"):
                print(f"Reason: {payload['skip_reason']}")
        return 1 if payload["status"] in {"failed", "blocked"} else 0

    if args.command == "sqlite-fts-benchmark":
        try:
            payload = run_sqlite_fts_benchmark(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                record_count=args.record_count,
                keyword=args.keyword,
                query_iterations=args.query_iterations,
                hit_every=args.hit_every,
                overwrite=args.overwrite,
            )
        except (SqliteFtsBenchmarkError, OSError, sqlite3.Error) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            metrics = payload["metrics"]
            print(f"Saved SQLite FTS benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved SQLite FTS benchmark report: {payload['outputs']['markdown']}")
            print(
                "SQLite FTS: "
                f"{metrics['record_count']} rows, query p95 {metrics['query_p95_seconds']}s, "
                f"expected hits {metrics['expected_hit_count']}"
            )
        return 0

    if args.command == "known-answer-qc":
        try:
            payload = run_known_answer_qc(
                manifest_path=Path(args.manifest).expanduser().resolve(),
                trusted_manifest_path=Path(args.trusted_manifest).expanduser().resolve() if args.trusted_manifest else None,
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
            )
        except (ValidationError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved known-answer QC JSON: {payload['outputs']['json']}")
            print(f"Saved known-answer QC report: {payload['outputs']['markdown']}")
            print(f"Status: {payload['summary']['status']}  Datasets: {payload['summary']['dataset_count']}")
        return 0

    if args.command == "sqlite-wal-preview":
        try:
            payload = build_sqlite_wal_preview(
                database_path=Path(args.database).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                max_frames=args.max_frames,
                preferred_trusted_tool=args.preferred_trusted_tool,
                trusted_tool_timeout_seconds=args.trusted_tool_timeout_seconds,
            )
        except (SqliteWalPreviewError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved SQLite WAL preview JSON: {payload['outputs']['json']}")
            print(f"Saved SQLite WAL preview report: {payload['outputs']['markdown']}")
            print(f"WAL status: {payload['wal']['status']}")
        return 0

    if args.command == "validation":
        try:
            payload = build_validation_package(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                overwrite=args.overwrite,
                known_answer_manifest=Path(args.known_answer_manifest).expanduser().resolve()
                if args.known_answer_manifest
                else None,
                fixture_root=Path(args.fixture_root).expanduser().resolve() if args.fixture_root else None,
                independent_report=Path(args.independent_report).expanduser().resolve() if args.independent_report else None,
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

    if args.command == "validation-diff-runners":
        payload = build_validation_diff_runner_matrix(
            search_path=build_tool_search_path(args.search_path),
            probe_versions=args.probe_versions,
            version_probe_timeout_seconds=max(float(args.version_timeout_seconds), 0.1),
        )
        if args.output:
            payload["output_manifest"] = write_validation_diff_runner_matrix(
                payload,
                Path(args.output).expanduser().resolve(),
            )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage validation diff runner matrix")
            print(f"QC items: {payload['qc_prep_item_numbers']}")
            print(
                f"Runner groups: {summary['runner_group_count']}  "
                f"Tools: {summary['available_tool_count']}/{summary['trusted_tool_count']} available"
            )
            if payload.get("output_manifest"):
                print(f"Saved matrix: {payload['output_manifest']['output']}")
        return 0

    if args.command == "final-qc-report":
        payload = build_final_qc_execution_report(
            validation_package=Path(args.validation_package).expanduser().resolve() if args.validation_package else None,
            runner_matrix=Path(args.runner_matrix).expanduser().resolve() if args.runner_matrix else None,
            chain_of_custody=Path(args.chain_of_custody).expanduser().resolve() if args.chain_of_custody else None,
            audit_bundle=Path(args.audit_bundle).expanduser().resolve() if args.audit_bundle else None,
            exhibit_bundle=Path(args.exhibit_bundle).expanduser().resolve() if args.exhibit_bundle else None,
            performance_runs=[Path(path).expanduser().resolve() for path in args.performance_run or []],
            browser_traces=[Path(path).expanduser().resolve() for path in args.browser_trace or []],
            reviewer_signoffs=[Path(path).expanduser().resolve() for path in args.reviewer_signoff or []],
        )
        if args.output:
            payload["output_manifest"] = write_final_qc_execution_report(
                payload,
                Path(args.output).expanduser().resolve(),
            )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage final QC execution report")
            print(f"QC items: {payload['qc_prep_item_numbers']}")
            print(f"Status: {payload['status']}")
            print(f"Failed checks: {len(payload['final_qc_checklist']['failed_check_ids'])}")
            if payload.get("output_manifest"):
                print(f"Saved report: {payload['output_manifest']['output']}")
        return 0

    if args.command == "commercial-readiness":
        try:
            payload = build_commercial_readiness_report(
                backlog_path=Path(args.backlog).expanduser().resolve() if args.backlog else None,
                output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
                validation_package_path=(
                    Path(args.validation_package).expanduser().resolve() if args.validation_package else None
                ),
                uplift_targets=args.uplift_targets,
                uplift_batch_size=args.uplift_batch_size,
            )
        except CommercialReadinessError as exc:
            parser.error(str(exc))
        focused_items = []
        if args.next_gate:
            focused_items = [
                item
                for item in payload.get("all_items", [])
                if isinstance(item, dict) and item.get("next_required_gate") == args.next_gate
            ]
            focused_items = focused_items[: max(args.limit, 0)]
            payload["focused_next_gate"] = args.next_gate
            payload["focused_items"] = focused_items
        elif args.limit != 25:
            payload["priority_work_plan"] = payload.get("priority_work_plan", [])[: max(args.limit, 0)]
        if args.write_known_answer_template:
            template_next_gate = args.next_gate or "validated"
            template_payload = build_known_answer_manifest_template(
                payload.get("all_items", []),
                next_gate=template_next_gate,
                limit=args.limit,
            )
            template_outputs = write_known_answer_manifest_template(
                template_payload,
                Path(args.write_known_answer_template).expanduser().resolve(),
            )
            template_payload["outputs"] = template_outputs
            payload["known_answer_manifest_template"] = template_payload
        if args.write_known_answer_template_dir:
            template_next_gate = args.next_gate or "validated"
            try:
                template_item_numbers = parse_item_range(args.template_items)
                batch_payload = build_known_answer_template_batches(
                    payload.get("all_items", []),
                    item_numbers=template_item_numbers,
                    batch_size=args.template_batch_size,
                    next_gate=template_next_gate,
                )
                batch_outputs = write_known_answer_template_batches(
                    batch_payload,
                    Path(args.write_known_answer_template_dir).expanduser().resolve(),
                )
            except CommercialReadinessError as exc:
                parser.error(str(exc))
            batch_payload["outputs"] = batch_outputs
            payload["known_answer_manifest_template_batches"] = batch_payload
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage commercial readiness gate")
            print(f"Status: {payload['status']}")
            print(f"Readiness score: {payload['readiness_score']}/100")
            print(f"Non-commercial items: {payload['non_commercial_count']}/{payload['item_count']}")
            print(f"Commercial claim allowed: {payload['commercial_claim_allowed']}")
            maturity_summary = payload.get("maturity_gate_summary")
            if isinstance(maturity_summary, dict):
                gate_counts = maturity_summary.get("gate_counts")
                if isinstance(gate_counts, dict):
                    print("Maturity gates:")
                    for gate_name in ("implemented", "usable", "validated", "commercial_grade"):
                        counts = gate_counts.get(gate_name)
                        if isinstance(counts, dict):
                            print(f"- {gate_name}: {counts.get('passed', 0)} passed / {counts.get('failed', 0)} remaining")
            validation_summary = payload.get("validation_evidence_summary")
            if isinstance(validation_summary, dict) and validation_summary.get("validation_package_attached"):
                print(
                    "Validation evidence attached: "
                    f"{validation_summary.get('items_with_passed_validation_evidence', 0)} items"
                )
            separation = payload.get("blocker_separation_profile")
            if isinstance(separation, dict):
                summary = separation.get("summary") if isinstance(separation.get("summary"), dict) else {}
                print(
                    "Blocker separation: "
                    f"internal work {summary.get('internal_work_available', 0)}, "
                    f"external/trusted evidence {summary.get('external_or_trusted_evidence_required', 0)}"
                )
            if args.next_gate:
                print(f"Focused next gate: {args.next_gate}")
                focus_source = focused_items
            else:
                focus_source = payload.get("priority_work_plan", [])
            if isinstance(focus_source, list) and focus_source:
                print("Priority work plan:")
                for item in focus_source[: max(args.limit, 0)]:
                    if not isinstance(item, dict):
                        continue
                    action = str(item.get("required_action") or item.get("remaining_gap") or item.get("release_gate") or "")
                    if len(action) > 140:
                        action = action[:137].rstrip() + "..."
                    print(
                        f"- #{item.get('number')} {item.get('title')} "
                        f"[{item.get('category')}, {item.get('severity')}, next={item.get('next_gate') or item.get('next_required_gate')}]: "
                        f"{action}"
                    )
            if payload.get("outputs"):
                outputs = payload["outputs"]
                print(f"Saved JSON: {outputs['json']}")
                print(f"Saved Markdown: {outputs['markdown']}")
            if payload.get("known_answer_manifest_template"):
                template = payload["known_answer_manifest_template"]
                if isinstance(template, dict) and isinstance(template.get("outputs"), dict):
                    outputs = template["outputs"]
                    print(f"Saved known-answer template JSON: {outputs['json']}")
                    print(f"Saved known-answer template Markdown: {outputs['markdown']}")
            if payload.get("known_answer_manifest_template_batches"):
                batches = payload["known_answer_manifest_template_batches"]
                if isinstance(batches, dict) and isinstance(batches.get("outputs"), dict):
                    outputs = batches["outputs"]
                    print(f"Saved known-answer batch index JSON: {outputs['index_json']}")
                    print(f"Saved known-answer batch index Markdown: {outputs['index_markdown']}")
                    print(f"Known-answer batches: {outputs['batch_count']}")
        return 1 if args.strict and not payload["commercial_claim_allowed"] else 0

    if args.command == "forensic-validation-plan":
        try:
            payload = build_forensic_validation_plan(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.output_dir:
            payload["outputs"] = write_forensic_validation_plan(payload, Path(args.output_dir).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic validation plan")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Validated: {summary['validated_count']}/{summary['item_count']}")
            print(f"Commercial-ready: {summary['commercial_grade_ready_count']}/{summary['item_count']}")
            print("Highest-priority open items:")
            for number in summary["highest_priority_open_items"]:
                row = next((item for item in payload["rows"] if item["number"] == number), None)
                if row:
                    print(f"- #{number} {row['title']} [{row['lane']}]: {row['next_internal_work']}")
            if payload.get("outputs"):
                outputs = payload["outputs"]
                print(f"Saved JSON: {outputs['json']}")
                print(f"Saved Markdown: {outputs['markdown']}")
        return 0

    if args.command == "forensic-validation-pack":
        try:
            payload = build_forensic_validation_pack(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except ValueError as exc:
            parser.error(str(exc))
        payload["outputs"] = write_forensic_validation_pack(payload, Path(args.output_dir).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic validation pack")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Required datasets: {summary['required_dataset_count']}")
            print(f"Required checks: {summary['required_check_count']}")
            print("Required tool families:")
            for tool in summary["required_tool_families"]:
                print(f"- {tool}")
            outputs = payload["outputs"]
            print(f"Saved JSON: {outputs['json']}")
            print(f"Saved Markdown: {outputs['markdown']}")
            print(f"Saved dataset template: {outputs['dataset_template']}")
            print(f"Saved command checklist: {outputs['reference_commands']}")
        return 0

    if args.command == "forensic-validation-pack-assess":
        try:
            payload = assess_forensic_validation_pack(
                Path(args.pack).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation pack assessment")
            print(f"Datasets: {payload['ready_dataset_count']}/{payload['dataset_count']} validation-ready")
            print(f"Commercial-ready datasets: {payload['commercial_ready_dataset_count']}/{payload['dataset_count']}")
            print(f"Ready for validated gate: {payload['ready_for_validated_gate']}")
            print(f"Ready for commercial grade: {payload['ready_for_commercial_grade']}")
            if payload.get("remaining_blockers"):
                print("Remaining blockers:")
                for blocker in payload["remaining_blockers"]:
                    print(f"- {blocker}")
        return 0

    if args.command == "forensic-validation-batches":
        try:
            payload = write_forensic_validation_batches(
                item_range=args.items,
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except ValueError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation batches")
            print(f"Items: {payload['item_range']} ({payload['item_count']})")
            print(f"Batches: {payload['batch_count']}")
            if payload.get("outputs"):
                print(f"Saved JSON: {payload['outputs']['json']}")
                print(f"Saved Markdown: {payload['outputs']['markdown']}")
        return 0

    if args.command == "forensic-validation-batches-assess":
        try:
            payload = assess_forensic_validation_batches(
                Path(args.root_dir).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage forensic validation batch assessment")
            print(f"Batches: {payload['batch_count']}")
            print(f"Datasets: {payload['ready_dataset_count']}/{payload['dataset_count']} validation-ready")
            print(f"External datasets: {payload['external_ready_dataset_count']}/{payload['dataset_count']} external-validation-ready")
            print(f"Commercial-ready datasets: {payload['commercial_ready_dataset_count']}/{payload['dataset_count']}")
            print(f"Ready for validated gate: {payload['ready_for_validated_gate']}")
            print(f"Ready for external validated gate: {payload['ready_for_external_validated_gate']}")
        if args.strict_commercial and not payload["ready_for_commercial_grade"]:
            return 2
        if args.strict_external and not payload["ready_for_external_validated_gate"]:
            return 2
        return 0

    if args.command == "forensic-validation-smoke-populate":
        try:
            payload = populate_forensic_validation_smoke_fixtures(
                Path(args.root_dir).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            assessment = payload["assessment"]
            print("RapidTriage forensic validation smoke population")
            print(f"Populated datasets: {payload['populated_dataset_count']}")
            print(f"Batches: {assessment['batch_count']}")
            print(f"Datasets: {assessment['ready_dataset_count']}/{assessment['dataset_count']} validation-ready")
            print(f"External datasets: {assessment['external_ready_dataset_count']}/{assessment['dataset_count']} external-validation-ready")
            print("Commercial-ready: false (internal smoke fixtures only)")
        return 0

    if args.command == "forensic-validation-evidence-import":
        try:
            payload = import_forensic_validation_evidence_manifest(
                Path(args.root_dir).expanduser().resolve(),
                Path(args.manifest).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            assessment = payload["assessment"]
            print("RapidTriage forensic validation evidence import")
            print(f"Imported datasets: {payload['imported_dataset_count']}")
            print(f"Missing datasets: {payload['missing_dataset_count']}")
            print(f"External datasets: {assessment['external_ready_dataset_count']}/{assessment['dataset_count']} external-validation-ready")
            print(f"Ready for external validated gate: {assessment['ready_for_external_validated_gate']}")
        return 0

    if args.command == "cross-tool-validate":
        references: dict[str, Path] = {}
        for value in args.reference_output or []:
            if "=" not in value:
                parser.error("--reference-output must use NAME=PATH")
            name, path = value.split("=", 1)
            if not name.strip() or not path.strip():
                parser.error("--reference-output must use NAME=PATH")
            references[name.strip()] = Path(path).expanduser().resolve()
        tool_versions = parse_named_cli_values(args.tool_version or [], option_name="--tool-version", parser=parser)
        tool_commands = parse_named_cli_values(args.tool_command or [], option_name="--tool-command", parser=parser)
        try:
            payload = build_cross_tool_validation_report(
                rapid_output=Path(args.rapid_output).expanduser().resolve(),
                reference_outputs=references,
                output=Path(args.output).expanduser().resolve() if args.output else None,
                min_overlap=args.min_overlap,
                backlog_items=args.backlog_item or [],
                tool_versions=tool_versions,
                tool_commands=tool_commands,
                source_evidence=[Path(path).expanduser().resolve() for path in args.source_evidence or []],
                independent_reports=[Path(path).expanduser().resolve() for path in args.independent_report or []],
                corpus_scope=args.corpus_scope or "",
            )
        except (CrossToolValidationError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage cross-tool validation")
            print(f"Status: {payload['status']}")
            for item in payload["comparisons"]:
                print(
                    f"- {item['reference_name']}: status={item['status']} "
                    f"overlap={item['overlap_ratio']} row_delta={item['row_count_delta']}"
                )
            if payload.get("output"):
                print(f"Saved report: {payload['output']}")
        return 0

    if args.command == "usn-state-replay-template":
        try:
            payload = write_usn_state_replay_known_answer_template(
                Path(args.output).expanduser().resolve(),
                include_examples=not args.empty,
            )
        except OSError as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage USN state replay known-answer template")
            print(f"Saved CSV: {payload['csv_path']}")
            print(f"Saved manifest: {payload['manifest_path']}")
            print(f"Rows: {payload['row_count']}")
            print(f"Trusted tool name: {payload['trusted_tool_name']}")
        return 0

    if args.command == "run-attach-validation-diff":
        diff_outputs = {
            name: Path(path).expanduser().resolve()
            for name, path in parse_named_cli_values(
                args.diff_output or [],
                option_name="--diff-output",
                parser=parser,
            ).items()
        }
        try:
            payload = attach_validation_diff_outputs(
                Path(args.run_output).expanduser().resolve(),
                diff_outputs,
                overwrite=args.overwrite,
            )
        except (RunValidationAttachmentError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage run validation diff attachment")
            print(f"Summary: {payload['summary_path']}")
            print(f"Attached outputs: {payload['attached_count']}")
            print(f"Audit: {payload['audit_path']}")
            print("Next: open the run in the web workbench or export its validation package.")
        return 0

    if args.command == "confidence-dashboard":
        try:
            payload = build_confidence_dashboard(
                Path(args.run_output).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            counts = payload["summary"]["confidence_counts"]
            print("RapidTriage evidence confidence dashboard")
            print(f"Status: {payload['status']}")
            print(
                "Counts: "
                f"report-grade={counts['report-grade']} "
                f"needs-validation={counts['needs-validation']} "
                f"triage={counts['triage']} unsupported={counts['unsupported']}"
            )
            if payload.get("output"):
                print(f"Saved dashboard: {payload['output']}")
        return 0

    if args.command == "parser-explainability":
        try:
            payload = build_parser_explainability(
                Path(args.run_output).expanduser().resolve(),
                output=Path(args.output).expanduser().resolve() if args.output else None,
                markdown_output=Path(args.markdown_output).expanduser().resolve() if args.markdown_output else None,
                limit=args.limit,
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage parser explainability")
            print(f"Entries: {payload['summary']['entry_count']}")
            print(f"Incomplete: {payload['summary']['incomplete_count']}")
            if payload.get("output"):
                print(f"Saved JSON: {payload['output']}")
            if payload.get("markdown_output"):
                print(f"Saved Markdown: {payload['markdown_output']}")
        return 0

    if args.command == "reproducibility-kit":
        try:
            payload = build_reproducibility_kit(
                baseline_run=Path(args.baseline_run).expanduser().resolve(),
                candidate_run=Path(args.candidate_run).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
            )
        except (ConfidenceDashboardError, OSError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("RapidTriage reproducibility kit")
            print(f"Status: {payload['status']}")
            print(f"Diff count: {payload['summary']['diff_count']}")
            print(f"Saved JSON: {payload['outputs']['json']}")
            print(f"Saved Markdown: {payload['outputs']['markdown']}")
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

    if args.command == "keyword-packs":
        payload = {
            "command": "keyword-packs",
            "packs": list_keyword_packs(),
            "keyword_pack_library_assessment": keyword_pack_library_assessment(),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            for pack in payload["packs"]:
                print(f"- {pack['name']}: {pack['keyword_count']} keywords")
        return 0

    if args.command == "search":
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            resolved_keywords = resolve_keyword_packs(
                args.keyword,
                pack_names=args.keyword_pack,
                pack_files=[Path(path) for path in (args.keyword_pack_file or [])],
            )
        except KeywordPackError as exc:
            parser.error(str(exc))
        try:
            payload = run_unified_search(
                run_output,
                resolved_keywords,
                include_ocr=not args.no_ocr,
                limit=args.limit,
                include_analysis=not args.no_analysis,
                search_mode=args.search_mode,
                fuzzy_distance=args.fuzzy_distance,
                proximity_window=args.proximity_window,
            )
            if args.keyword_pack or args.keyword_pack_file:
                payload["keyword_pack_selection_profile"] = keyword_pack_selection_profile(
                    pack_names=args.keyword_pack or [],
                    keyword_count=len(resolved_keywords),
                    custom_file_count=len(args.keyword_pack_file or []),
                    expanded_keywords=resolved_keywords,
                )
        except SearchError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="search",
            options={
                "keywords": resolved_keywords,
                "output": str(output),
                "limit": args.limit,
                "ocr": not args.no_ocr,
                "analysis": not args.no_analysis,
                "search_mode": args.search_mode,
                "fuzzy_distance": args.fuzzy_distance,
                "proximity_window": args.proximity_window,
                "keyword_pack": args.keyword_pack or [],
                "keyword_pack_file": args.keyword_pack_file or [],
            },
            input_files=[("run-summary", input_summary)],
            output_files=[("search-json", output)],
        )
        print(f"Saved search JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        print(f"Matches: {payload['summary']['match_count']}")
        return 0

    if args.command == "source-read":
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_source_read(
                run_output,
                args.path,
                include_hashes=args.hash,
                max_chars=args.max_chars,
                hex_bytes=args.hex_bytes,
                sqlite_table=args.sqlite_table,
                sqlite_offset=args.sqlite_offset,
                sqlite_limit=args.sqlite_limit,
                sqlite_where_column=args.sqlite_where_column,
                sqlite_where_contains=args.sqlite_where_contains,
            )
        except SourceReadError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="source-read",
            options={
                "path": args.path,
                "output": str(output),
                "max_chars": args.max_chars,
                "hex_bytes": args.hex_bytes,
                "sqlite_table": args.sqlite_table,
                "sqlite_offset": args.sqlite_offset,
                "sqlite_limit": args.sqlite_limit,
                "sqlite_where_column": args.sqlite_where_column,
                "sqlite_where_contains": bool(args.sqlite_where_contains),
                "hash": args.hash,
            },
            input_files=[("run-summary", input_summary), ("source-file", Path(str(payload["path"])))],
            output_files=[("source-read-json", output)],
        )
        print(f"Saved source-read JSON: {output}")
        print(f"Saved audit JSON: {audit_output}")
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(render_source_read_text(payload))
        return 0

    if args.command == "ocr-queue":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        previous = Path(args.previous).expanduser().resolve() if args.previous else None
        try:
            payload = build_ocr_queue(
                root,
                previous_queue=previous,
                retry_failures=args.retry_failures,
                max_items=args.max_items,
            )
        except OcrQueueError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="ocr-queue",
            options={
                "root": str(root),
                "output": str(output),
                "previous": str(previous) if previous else "",
                "retry_failures": args.retry_failures,
                "max_items": args.max_items,
            },
            input_files=[("root", root), *([("previous-queue", previous)] if previous else [])],
            output_files=[("ocr-queue-json", output)],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved OCR queue JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Candidates: {payload['summary']['candidate_count']}")
        return 0

    if args.command == "indicators":
        run_output = Path(args.run_output).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = build_indicator_summary(
                run_output,
                rule_set=rule_set,
                ti_feeds=[Path(path) for path in (args.ti_feed or [])],
                max_indicators=args.limit,
                max_sources_per_indicator=args.max_sources,
            )
        except IndicatorSummaryError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        input_summary = run_output / "rapidtriage-run-summary.json" if run_output.is_dir() else run_output
        write_audit_record(
            audit_output,
            command="indicators",
            options={
                "output": str(output),
                "limit": args.limit,
                "max_sources": args.max_sources,
                "rules": str(rule_set.path) if rule_set else None,
                "ti_feed": args.ti_feed or [],
            },
            input_files=[("run-summary", input_summary)],
            output_files=[("indicators-json", output)],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved indicators JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Indicators: {payload['summary']['indicator_count']}")
        return 0

    if args.command == "compare":
        compare_paths_input = [Path(value).expanduser().resolve() for value in args.paths]
        if len(compare_paths_input) < 2:
            parser.error("compare requires at least two files")
        output = Path(args.output).expanduser().resolve()
        try:
            if len(compare_paths_input) == 2:
                payload = compare_paths(
                    compare_paths_input[0],
                    compare_paths_input[1],
                    left_label=args.left_label,
                    right_label=args.right_label,
                    hash_files=not args.no_hash,
                    include_text_diff=not args.no_text_diff,
                    max_text_bytes=args.max_text_bytes,
                    diff_context=args.diff_context,
                    selection_rationale=args.selection_rationale,
                    review_notes=args.review_note,
                )
            else:
                payload = compare_many_paths(
                    compare_paths_input,
                    labels=args.label,
                    hash_files=not args.no_hash,
                    include_text_diff=not args.no_text_diff,
                    max_text_bytes=args.max_text_bytes,
                    diff_context=args.diff_context,
                    selection_rationale=args.selection_rationale,
                    review_notes=args.review_note,
                )
        except CompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="compare",
            options={
                "paths": [str(path) for path in compare_paths_input],
                "left_label": args.left_label,
                "right_label": args.right_label,
                "labels": args.label or [],
                "output": str(output),
                "hash": not args.no_hash,
                "text_diff": not args.no_text_diff,
                "max_text_bytes": args.max_text_bytes,
                "diff_context": args.diff_context,
                "selection_rationale": args.selection_rationale,
                "review_note_count": len(args.review_note or []),
            },
            input_files=[(f"input:{index}", path) for index, path in enumerate(compare_paths_input, start=1)],
            output_files=[("compare-json", output)],
            notes=[
                "Compare output is review-oriented; preserve the original files and hashes for evidentiary submission.",
                "Use vsc-compare for directory tree or Volume Shadow Copy comparisons.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            status_counts = summary.get("status_counts", {})
            status_text = ", ".join(f"{key}={value}" for key, value in status_counts.items())
            print(f"Saved compare JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Results: {summary['result_count']}  Status: {status_text or 'none'}")
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

    if args.command == "vsc-discover":
        current_root = Path(args.current_root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = discover_vsc_snapshot_roots(current_root, max_depth=args.max_depth)
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-discover",
            options={
                "current_root": str(current_root),
                "output": str(output),
                "max_depth": args.max_depth,
            },
            input_root=current_root,
            output_files=[("vsc-discovery-json", output)],
            notes=[
                "Discovery searches for mounted/exported snapshot folders by name; it does not mount VSC from an E01/RAW image.",
                "Use vsc-compare and vsc-extract after confirming the discovered snapshot roots.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved VSC discovery JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Snapshots: {payload['snapshot_count']}")
        return 0

    if args.command == "vsc-extract":
        current_root = Path(args.current_root).expanduser().resolve()
        snapshot_roots = [Path(item).expanduser().resolve() for item in args.snapshot_roots]
        output_dir = Path(args.output_dir).expanduser().resolve()
        output = Path(args.manifest).expanduser().resolve() if args.manifest else output_dir / "rapidtriage-vsc-extract.json"
        try:
            payload = extract_vsc_changes(
                current_root,
                snapshot_roots,
                output_dir,
                statuses=args.status or ["deleted", "modified"],
                compute_hashes=not args.no_hash,
                case_sensitive=args.case_sensitive,
                max_records=args.max_records,
                max_file_count=args.max_file_count,
                max_total_bytes=args.max_total_bytes,
                overwrite=args.overwrite,
            )
        except VscCompareError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="vsc-extract",
            options={
                "current_root": str(current_root),
                "snapshot_roots": [str(path) for path in snapshot_roots],
                "output_dir": str(output_dir),
                "manifest": str(output),
                "status": args.status or ["deleted", "modified"],
                "hash": not args.no_hash,
                "case_sensitive": args.case_sensitive,
                "overwrite": args.overwrite,
                "max_records": args.max_records,
                "max_file_count": args.max_file_count,
                "max_total_bytes": args.max_total_bytes,
            },
            input_root=current_root,
            output_files=[("vsc-extract-json", output), ("vsc-extract-evidence", Path(str(payload["evidence_root"])))],
            notes=[
                "VSC extract copies selected snapshot/current files into an evidence folder and records SHA256 values.",
                "Deleted and modified statuses preserve the snapshot-side file; added status preserves the current-side file.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved VSC extract JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Selected: {summary['selected_count']}  "
                f"Copied: {summary['copied_count']}  Skipped: {summary['skipped_count']}"
            )
        return 0

    if args.command == "carve":
        input_root = resolve_input_root(Path(args.root), kind=args.input_kind)
        output_dir = Path(args.output_dir).expanduser().resolve()
        try:
            payload = run_bounded_carving(
                input_root,
                output_dir,
                extract=args.extract,
                max_scan_bytes=args.max_scan_bytes,
                max_carve_bytes=args.max_carve_bytes,
                max_candidates=args.max_candidates,
                extensions=args.ext,
            )
        except (CarvingError, OSError, ValueError) as exc:
            parser.error(str(exc))
        output = output_dir / "rapidtriage-carve.json"
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="carve",
            options={
                "output_dir": str(output_dir),
                "extract": args.extract,
                "max_scan_bytes": args.max_scan_bytes,
                "max_carve_bytes": args.max_carve_bytes,
                "max_candidates": args.max_candidates,
                "extensions": args.ext or [],
            },
            input_root=input_root,
            output_files=[("carve-json", output)]
            + [
                (f"carved:{entry['kind']}:{entry['offset']}", Path(str(entry["extracted_path"])).resolve())
                for entry in payload.get("entries", [])
                if entry.get("extracted_path")
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved carve JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(f"Candidates: {payload['summary']['candidate_count']}  Extracted: {payload['summary']['extracted_count']}")
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

    if args.command == "kakaotalk-decrypt":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        decrypted_dir = Path(args.decrypted_dir).expanduser().resolve() if args.decrypted_dir else None
        try:
            payload = run_kakaotalk_decrypt(
                root,
                output=output,
                key_hex=args.key_hex,
                iv_hex=args.iv_hex,
                pragma=args.pragma,
                user_id=args.user_id,
                pragma_key_hex=args.pragma_key_hex,
                sys_uuid=args.sys_uuid,
                hdd_model=args.hdd_model,
                hdd_serial=args.hdd_serial,
                key_hex_env=args.key_hex_env,
                iv_hex_env=args.iv_hex_env,
                pragma_env=args.pragma_env,
                user_id_env=args.user_id_env,
                pragma_key_hex_env=args.pragma_key_hex_env,
                sys_uuid_env=args.sys_uuid_env,
                hdd_model_env=args.hdd_model_env,
                hdd_serial_env=args.hdd_serial_env,
                include_message_preview=args.include_message_preview,
                write_decrypted=args.write_decrypted,
                decrypted_dir=decrypted_dir,
                max_databases=args.max_databases,
                max_messages_per_db=args.max_messages_per_db,
                openssl_bin=args.openssl_bin,
                postpatch_memory_carve=not args.no_postpatch_memory_carve,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-decrypt",
            options={
                "output": str(output),
                "include_message_preview": args.include_message_preview,
                "write_decrypted": args.write_decrypted,
                "decrypted_dir": str(decrypted_dir) if decrypted_dir else None,
                "max_databases": args.max_databases,
                "max_messages_per_db": args.max_messages_per_db,
                "openssl_bin": args.openssl_bin,
                "postpatch_memory_carve": not args.no_postpatch_memory_carve,
                "auth_material_source": payload["auth_material"]["source"],
                "auth_material_ready": payload["auth_material"]["ready"],
                "secrets_redacted": True,
            },
            output_files=[("kakaotalk-decrypt-json", output)]
            + (
                [
                    ("decrypted-dir", Path(str(payload["entries"][0]["decrypted_path"])).parent)
                    for _ in [0]
                    if args.write_decrypted
                    and payload.get("entries")
                    and payload["entries"][0].get("decrypted_path")
                ]
            ),
            notes=[
                "KakaoTalk secrets are intentionally redacted from the audit log.",
                "Message previews are included only when --include-message-preview is set.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk decrypt JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Chat DBs: {summary['chat_database_count']}  "
                f"SQLite opened: {summary['sqlite_open_count']}  "
                f"Messages: {summary['message_row_count']}"
            )
            if "postpatch_memory_carve" in payload:
                print(
                    "Post-patch memory carve: "
                    f"SQLite headers {summary.get('postpatch_memory_carve_sqlite_header_count', 0)}  "
                    f"DB fragments {summary.get('postpatch_memory_carve_database_count', 0)}  "
                    f"chat-relevant tables {summary.get('postpatch_memory_carve_chat_relevant_table_count', 0)}  "
                    f"message residues {summary.get('postpatch_memory_chat_message_residue_count', 0)}"
                )
        return 0

    if args.command == "kakaotalk-macos-report":
        root = Path(args.root).expanduser().resolve()
        output_dir = Path(args.output_dir).expanduser().resolve()
        previous_user_id_file = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE")
        if args.user_id_file:
            os.environ["RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE"] = str(Path(args.user_id_file).expanduser().resolve())
        try:
            payload = run_kakaotalk_macos_report(
                root,
                output_dir=output_dir,
                include_message_text=args.include_message_text,
                max_messages=args.max_messages,
                sqlcipher_bin=args.sqlcipher_bin,
            )
        except (KakaoTalkMacOsReportError, OSError, ValueError) as exc:
            parser.error(str(exc))
        finally:
            if args.user_id_file:
                if previous_user_id_file is None:
                    os.environ.pop("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE", None)
                else:
                    os.environ["RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE"] = previous_user_id_file
        outputs = payload.get("outputs") if isinstance(payload.get("outputs"), dict) else {}
        report_json = Path(str(outputs.get("report_json", output_dir / "kakaotalk_macos_report.json")))
        audit_output = audit_path_for(report_json)
        output_files = [
            (str(label), Path(str(path)))
            for label, path in outputs.items()
            if isinstance(path, str)
        ]
        write_audit_record(
            audit_output,
            command="kakaotalk-macos-report",
            options={
                "output_dir": str(output_dir),
                "include_message_text": args.include_message_text,
                "max_messages": args.max_messages,
                "user_id_file": str(Path(args.user_id_file).expanduser().resolve()) if args.user_id_file else None,
                "sqlcipher_bin": args.sqlcipher_bin,
                "raw_user_id_exported": False,
                "sqlcipher_key_exported": False,
            },
            input_root=root,
            output_files=output_files,
            notes=[
                "macOS KakaoTalk SQLCipher stores are opened read-only with -ifexists when sqlcipher is required.",
                "Raw Kakao UserID and SQLCipher key values are kept in memory and are not written to report or audit JSON.",
                "Message text is exported only when --include-message-text is explicitly set.",
            ],
        )
        payload["audit_output"] = str(audit_output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved macOS KakaoTalk report JSON: {outputs.get('report_json')}")
            print(f"Saved macOS KakaoTalk viewer HTML: {outputs.get('viewer_html')}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Databases: {summary['processed_database_count']}/{summary['database_count']}  "
                f"SQLCipher opened: {summary['sqlcipher_opened_count']}  "
                f"Plain SQLite opened: {summary['plain_sqlite_opened_count']}  "
                f"Messages: {summary['message_count']}  "
                f"Media refs: {summary['media_reference_count']}"
            )
        return 0

    if args.command == "kakaotalk-collect-windows":
        output_root = Path(args.output_root).expanduser().resolve()
        kakao_root = Path(args.kakao_root).expanduser().resolve() if args.kakao_root else None
        try:
            payload = run_kakaotalk_windows_collect(
                output_root=output_root,
                kakao_root=kakao_root,
                include_memory_dump=args.include_memory_dump,
                analyze=args.analyze,
                sqlcipher_bin=args.sqlcipher_bin,
                timeout_seconds=args.timeout_seconds,
                max_message_residues=args.max_message_residues,
                no_xlsx=args.no_xlsx,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        collection_zip = Path(str(payload["summary"]["collection_zip"]))
        audit_output = audit_path_for(collection_zip)
        output_files = [("kakaotalk-collection-zip", collection_zip)]
        if payload["summary"].get("report_dir"):
            output_files.append(("kakaotalk-collection-report-dir", Path(str(payload["summary"]["report_dir"]))))
        write_audit_record(
            audit_output,
            command="kakaotalk-collect-windows",
            options={
                "output_root": str(output_root),
                "kakao_root": str(kakao_root) if kakao_root else None,
                "include_memory_dump": args.include_memory_dump,
                "analyze": args.analyze,
                "sqlcipher_bin": args.sqlcipher_bin,
                "timeout_seconds": args.timeout_seconds,
                "max_message_residues": args.max_message_residues,
                "sensitive_keys_exported": False,
            },
            output_files=output_files,
            notes=[
                "Collect only systems and accounts within authorized legal scope.",
                "Memory dumps are collected only when explicitly requested.",
                "Sensitive key material is not exported by the collection workflow.",
            ],
        )
        payload["audit_output"] = str(audit_output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk collection ZIP: {summary['collection_zip']}")
            print(f"Saved audit JSON: {audit_output}")
            if summary.get("report_dir"):
                print(f"Saved KakaoTalk report directory: {summary['report_dir']}")
            print(
                f"Files hashed: {summary['hash_manifest_count']}  "
                f"Registry exports: {summary['registry_export_count']}  "
                f"Memory dumps: {summary['memory_dump_count']}  "
                f"status: {summary['status']}"
            )
        return 0

    if args.command == "kakaotalk-memory-carve":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        carve_dir = Path(args.carve_dir).expanduser().resolve() if args.carve_dir else None
        message_csv = Path(args.message_csv).expanduser().resolve() if args.message_csv else None
        try:
            payload = run_kakaotalk_memory_carve(
                root,
                output=output,
                carve_dir=carve_dir,
                max_hits=args.max_hits,
                max_carve_bytes=args.max_carve_bytes,
                include_row_preview=args.include_row_preview,
                max_rows_per_table=args.max_rows_per_table,
                max_message_residues=args.max_message_residues,
                include_message_preview=args.include_message_preview or args.include_row_preview or bool(message_csv),
                write_carves=args.write_carves,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        if message_csv is not None:
            write_kakaotalk_message_residue_csv(payload, message_csv)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-memory-carve",
            options={
                "output": str(output),
                "carve_dir": str(carve_dir) if carve_dir else None,
                "message_csv": str(message_csv) if message_csv else None,
                "write_carves": args.write_carves,
                "max_hits": args.max_hits,
                "max_carve_bytes": args.max_carve_bytes,
                "include_row_preview": args.include_row_preview,
                "include_message_preview": args.include_message_preview,
                "max_rows_per_table": args.max_rows_per_table,
                "max_message_residues": args.max_message_residues,
                "secrets_redacted": not (args.include_row_preview or args.include_message_preview or bool(message_csv)),
            },
            output_files=[("kakaotalk-memory-carve-json", output)]
            + ([("kakaotalk-message-residue-csv", message_csv)] if message_csv else [])
            + ([("kakaotalk-memory-carve-dir", carve_dir)] if args.write_carves and carve_dir else []),
            notes=[
                "Memory-carved SQLite fragments are post-patch triage evidence and require manual validation.",
                "Row previews are included only when --include-row-preview is set.",
                "Message body previews are included only when --include-message-preview or --message-csv is set.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk memory carve JSON: {output}")
            if message_csv is not None:
                print(f"Saved KakaoTalk message residue CSV: {message_csv}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Memory sources: {summary['memory_source_count']}  "
                f"SQLite headers: {summary['sqlite_header_count']}  "
                f"DB fragments: {summary['carved_database_count']}  "
                f"chat-relevant tables: {summary['chat_relevant_table_count']}  "
                f"message residues: {summary['chat_message_residue_count']}  "
                f"reverse indicators: {summary.get('reverse_indicator_count', 0)}  "
                f"SQLCipher key residues: {summary.get('sqlcipher_key_residue_count', 0)}"
            )
        return 0

    if args.command == "kakaotalk-sqlcipher-probe":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        export_opened_dir = Path(args.export_opened_dir).expanduser().resolve() if args.export_opened_dir else None
        try:
            payload = run_kakaotalk_sqlcipher_probe(
                root,
                output=output,
                sqlcipher_bin=args.sqlcipher_bin,
                max_keys=args.max_keys,
                max_databases=args.max_databases,
                max_message_residues=args.max_message_residues,
                include_message_preview=args.include_message_preview,
                timeout_seconds=args.timeout_seconds,
                export_opened_dir=export_opened_dir,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-sqlcipher-probe",
            options={
                "output": str(output),
                "sqlcipher_bin": args.sqlcipher_bin,
                "max_keys": args.max_keys,
                "max_databases": args.max_databases,
                "max_message_residues": args.max_message_residues,
                "include_message_preview": args.include_message_preview,
                "timeout_seconds": args.timeout_seconds,
                "export_opened_dir": str(export_opened_dir) if export_opened_dir else None,
                "raw_keys_redacted": True,
            },
            output_files=[("kakaotalk-sqlcipher-probe-json", output)]
            + ([("kakaotalk-opened-edb-export-dir", export_opened_dir)] if export_opened_dir else []),
            notes=[
                "SQLCipher probes run only against temporary EDB copies.",
                "Memory key literals are redacted in output and require manual validation.",
                "Plaintext SQLite exports are produced only for EDBs whose memory literal salt matches the file header.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk SQLCipher probe JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Chat DBs: {summary['chat_database_count']}  "
                f"key candidates: {summary['key_candidate_count']}  "
                f"variants: {summary['variant_count']}  "
                f"attempts: {summary['probe_attempt_count']}  "
                f"opened: {summary['opened_database_count']}  "
                f"openable EDBs: {summary.get('openable_edb_count', 0)}  "
                f"exported EDBs: {summary.get('exported_edb_count', 0)}  "
                f"rooms: {summary.get('postpatch_room_evidence_count', 0)}  "
                f"memory messages: {summary.get('postpatch_message_residue_count', 0)}  "
                f"media attachments: {summary.get('postpatch_media_attachment_count', 0)}  "
                f"local media files: {summary.get('postpatch_media_local_file_count', 0)}  "
                f"status: {summary['status']}"
            )
        return 0

    if args.command == "kakaotalk-key-store-inspect":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_kakaotalk_key_store_inspect(
                root,
                output=output,
                max_memory_sources=args.max_memory_sources,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-key-store-inspect",
            options={
                "output": str(output),
                "max_memory_sources": args.max_memory_sources,
                "raw_wrapped_deks_redacted": True,
                "unwrapped_deks_not_exported": True,
            },
            output_files=[("kakaotalk-key-store-json", output)],
            notes=[
                "appstate.dat wrapped DEKs are hashed and length-counted only; raw wrapped key bytes are not exported.",
                "This maps post-patch EDB key-store state but does not yet unwrap DEKs.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk key-store JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Key stores: {summary['parsed_key_store_count']}/{summary['key_store_file_count']}  "
                f"wrapped DEKs: {summary['wrapped_dek_entry_count']}  "
                f"chatLog keys: {summary['chatlog_wrapped_dek_entry_count']}  "
                f"chatLog file matches: {summary['chat_database_key_store_match_count']}  "
                f"status: {summary['method_status']}"
            )
        return 0

    if args.command == "kakaotalk-userdir-bruteforce":
        root = Path(args.root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            payload = run_kakaotalk_userdir_bruteforce(
                root,
                output=output,
                userdir_home=args.userdir_home,
                userdir=args.userdir,
                pragma=args.pragma,
                pragma_key_hex=args.pragma_key_hex,
                sys_uuid=args.sys_uuid,
                hdd_model=args.hdd_model,
                hdd_serial=args.hdd_serial,
                start_id=args.start_id,
                end_id=args.end_id,
                chunk_size=args.chunk_size,
                compiler=args.compiler,
                openssl_bin=args.openssl_bin,
            )
        except KakaoTalkDecryptError as exc:
            parser.error(str(exc))
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="kakaotalk-userdir-bruteforce",
            options={
                "output": str(output),
                "userdir": args.userdir,
                "userdir_home": args.userdir_home,
                "start_id": args.start_id,
                "end_id": args.end_id,
                "chunk_size": args.chunk_size,
                "compiler": args.compiler,
                "secrets_redacted": True,
            },
            output_files=[("kakaotalk-userdir-bruteforce-json", output)],
            notes=[
                "KakaoTalk pragma values are redacted from the audit log.",
                "A matched userId is sensitive and should be used only within authorized scope.",
            ],
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print(f"Saved KakaoTalk userDir brute force JSON: {output}")
            print(f"Saved audit JSON: {audit_output}")
            print(
                f"Status: {summary['status']}  "
                f"Searched through: {summary['searched_end_id']}  "
                f"Matched: {summary['matched']}"
            )
        return 0

    if args.command == "taxonomy-audit":
        repo_root = Path(args.repo_root).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        payload = build_taxonomy_audit(repo_root)
        write_result(payload, output)
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload["summary"]
            print("RapidTriage forensic artifact taxonomy audit")
            print(f"Saved taxonomy audit JSON: {output}")
            print(
                "Targets: "
                f"{summary['target_count']}  Covered: {summary['covered_count']}  "
                f"Partial: {summary['partial_count']}  Missing: {summary['missing_count']}"
            )
            print(
                "Implementation evidence: "
                f"collectors={summary['collector_count']}  "
                f"artifact_type_literals={summary['artifact_type_literal_count']}"
            )
            priority_missing = payload.get("priority_missing")
            if isinstance(priority_missing, list) and priority_missing:
                print("Priority missing targets:")
                for item in priority_missing[:8]:
                    if isinstance(item, dict):
                        print(f"- {item.get('id')}: {item.get('title')}")
            priority_partial = payload.get("priority_partial")
            if isinstance(priority_partial, list) and priority_partial:
                print("Priority partial targets:")
                for item in priority_partial[:8]:
                    if isinstance(item, dict):
                        print(f"- {item.get('id')}: {item.get('title')}")
        return 1 if args.strict and not payload["summary"]["strict_pass"] else 0

    if args.command == "email-external-parse":
        try:
            payload = run_email_external_parse(
                source_path=Path(args.source).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                preferred_tool=args.preferred_tool,
                timeout_seconds=args.timeout_seconds,
                overwrite=args.overwrite,
            )
        except (EmailExternalParserError, OSError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved email external parser JSON: {payload['outputs']['json']}")
            print(f"Saved email external parser report: {payload['outputs']['markdown']}")
            print(f"Status: {payload['status']}  Export files: {payload['summary']['export_file_count']}")
        return 1 if payload["status"] == "failed" else 0

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
                memory_cap_bytes=args.memory_cap_bytes,
                e01_partition_start_sector=getattr(args, "e01_partition_start_sector", None),
                overwrite=args.overwrite,
                resume=args.resume,
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
        if args.eventlog_message_catalog and args.kind != "eventlog":
            parser.error("--eventlog-message-catalog can only be used with --kind eventlog")
        output = (
            Path(args.output).expanduser().resolve()
            if args.output
            else (Path.cwd() / f"rapidtriage-artifacts-{args.kind}.json").resolve()
        )
        collector_options = {}
        if args.eventlog_message_catalog:
            collector_options["message_catalog_path"] = Path(args.eventlog_message_catalog).expanduser().resolve()
        try:
            payload = run_artifact_collection(
                root,
                kind=args.kind,
                input_kind=args.input_kind,
                rule_set=rule_set,
                collector_options=collector_options,
            )
        except ArtifactCollectionError as exc:
            parser.error(str(exc))
        write_result(payload, output)
        audit_output = audit_path_for(output)
        write_audit_record(
            audit_output,
            command="artifacts",
            options={
                "kind": args.kind,
                "output": str(output),
                "input_kind": args.input_kind,
                "rules": args.rules,
                "eventlog_message_catalog": args.eventlog_message_catalog,
            },
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
                known_good_hash_feeds=args.known_good_hash_feed,
                hide_known_good=args.hide_known_good,
                known_good_max_hash_bytes=args.known_good_max_hash_bytes,
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
                "known_good_hash_feeds": args.known_good_hash_feed,
                "hide_known_good": args.hide_known_good,
                "known_good_max_hash_bytes": args.known_good_max_hash_bytes,
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
