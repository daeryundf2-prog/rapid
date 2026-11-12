"""Choices and defaults shared by the argparse parsers and the engine (T-161b).

``rapidtriage --help`` builds every subcommand parser, and those parsers need
these values for ``choices=`` and ``default=``. They used to be imported from
the engine modules that own them, which pulled in ``rapidtriage.artifacts``
(and ``cv2``/``numpy``) just to print help. They live here instead, in a module
that imports nothing beyond the standard library; the engine modules re-export
them under their original names, so existing imports keep working.

Keep this module dependency-free: no ``rapidtriage`` imports, no third-party
imports. ``tests/test_cli_fast_help.py`` enforces that ``--help`` stays light.
"""

from __future__ import annotations

from pathlib import Path

# core.extract
SUPPORTED_DOC_KINDS: tuple[str, ...] = (
    "cfg",
    "conf",
    "csv",
    "docx",
    "eml",
    "htm",
    "html",
    "ini",
    "json",
    "jsonl",
    "log",
    "md",
    "odp",
    "ods",
    "odt",
    "pdf",
    "pptx",
    "rtf",
    "tsv",
    "txt",
    "xlsx",
    "xml",
    "yaml",
    "yml",
)
DEFAULT_EXTRACT_MANIFEST_NAME = "rapidtriage-extract-manifest.json"

# core.run.constants
SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")

# core.input_root
SUPPORTED_INPUT_ROOT_KINDS = ("folder", "mounted-image", "e01-derived", "disk-image-derived", "archive-image-derived", "live")

# core.case
REVIEW_STATUSES = ("unreviewed", "relevant", "needs-review", "not-relevant", "excluded")

# core.sample_case
DEFAULT_SAMPLE_DIR = "rapidtriage-sample"
DEFAULT_SAMPLE_MODE = "fraud"

# core.cloud_api
DEFAULT_CLOUD_BEARER_TOKEN_ENV = "RAPIDTRIAGE_CLOUD_BEARER_TOKEN"
DEFAULT_CLOUD_API_TIMEOUT_SECONDS = 30
DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES = 50 * 1024 * 1024

# core.collect_plan
DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT = 5000
DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024

# core.carving
DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CARVE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 250

# core.kakaotalk
DEFAULT_MEMORY_SQLITE_MAX_HITS = 200
DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES = 64 * 1024 * 1024
DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT = 200
DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT = 300

# artifacts.kakaotalk_macos
DEFAULT_MACOS_REPORT_MAX_MESSAGES = 100_000
DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS = 100_000

# core.benchmark
DEFAULT_BENCHMARK_FILE_COUNT = 100
DEFAULT_BENCHMARK_KEYWORD = "password"

# core.benchmark_fts
SQLITE_FTS_DEFAULT_RECORD_COUNT = 100_000
SQLITE_FTS_DEFAULT_QUERY_ITERATIONS = 5
SQLITE_FTS_DEFAULT_HIT_EVERY = 10

# core.browser_stress
DEFAULT_BROWSER_STRESS_RECORD_COUNT = 100_000

# core.commercial_readiness
MATURITY_GATE_ORDER = ("implemented", "usable", "validated", "commercial_grade")

# core.forensic_validation_plan
DEFAULT_FORENSIC_VALIDATION_ITEMS = "1-120"
DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS = "1-5"

# core.large_case_readiness
DEFAULT_LARGE_CASE_P95_THRESHOLD_MS = 1_000.0

# core.macos_live_smoke
DEFAULT_MACOS_SMOKE_BENCHMARK_FILES = 150
DEFAULT_MACOS_SMOKE_FTS_RECORDS = 2_000

# core.validation_diff_runners
VERSION_PROBE_TIMEOUT_SECONDS = 3.0


# core.case_catalog
def default_case_catalog_path() -> Path:
    return Path.home() / ".rapidtriage" / "case-catalog.json"
