"""Parser registration for benchmark, readiness and validation commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.cli_constants import (
    DEFAULT_BENCHMARK_FILE_COUNT,
    DEFAULT_BENCHMARK_KEYWORD,
    DEFAULT_BROWSER_STRESS_RECORD_COUNT,
    DEFAULT_FORENSIC_VALIDATION_ITEMS,
    DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
    DEFAULT_LARGE_CASE_P95_THRESHOLD_MS,
    DEFAULT_MACOS_SMOKE_BENCHMARK_FILES,
    DEFAULT_MACOS_SMOKE_FTS_RECORDS,
    MATURITY_GATE_ORDER,
    SQLITE_FTS_DEFAULT_HIT_EVERY,
    SQLITE_FTS_DEFAULT_QUERY_ITERATIONS,
    SQLITE_FTS_DEFAULT_RECORD_COUNT,
    SUPPORTED_RUN_MODES,
    VERSION_PROBE_TIMEOUT_SECONDS,
)


def register(sub: argparse._SubParsersAction) -> None:
    """Register benchmark through reproducibility-kit (benchmarks, stress, readiness, validation, QC)."""
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
