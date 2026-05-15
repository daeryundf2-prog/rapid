from __future__ import annotations

import contextlib
import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Mapping, Sequence

from .benchmark import scale_label
from .benchmark_fts import SQLITE_FTS_BENCHMARK_VERSION
from .case_db import case_db_fts_optimization_assessment
from .docs import write_result
from .search_backend import build_search_backend_contract, stable_backend_sha256


LARGE_CASE_READINESS_VERSION = "large-case-readiness-v1"
LARGE_CASE_READINESS_ITEM_NUMBERS = [66, 67, 74, 78, 79]
DEFAULT_LARGE_CASE_P95_THRESHOLD_MS = 1_000.0
CASE_DB_PROFILE_TABLES = [
    "case_record",
    "evidence_source",
    "file_record",
    "hash_record",
    "artifact",
    "event",
    "indexed_document",
    "review_mark",
    "saved_search",
    "audit_event",
    "report_item",
    "job",
    "job_step",
]


class LargeCaseReadinessError(ValueError):
    """Raised when large-case readiness inputs are missing or malformed."""


def build_large_case_readiness_report(
    *,
    case_db_path: Path | None = None,
    benchmark_paths: Sequence[Path] | None = None,
    keyword: str = "needle",
    max_query_p95_ms: float = DEFAULT_LARGE_CASE_P95_THRESHOLD_MS,
    output: Path | None = None,
) -> dict[str, object]:
    normalized_keyword = keyword.strip() or "needle"
    benchmarks = [
        load_sqlite_fts_benchmark(path.expanduser().resolve())
        for path in (benchmark_paths or [])
    ]
    case_db_profile = (
        profile_case_db(case_db_path.expanduser().resolve(), keyword=normalized_keyword)
        if case_db_path
        else {"attached": False}
    )
    checks = build_large_case_checks(
        benchmarks=benchmarks,
        case_db_profile=case_db_profile,
        max_query_p95_ms=max_query_p95_ms,
    )
    failed_checks = [check for check in checks if not check["passed"]]
    record_counts = [int(item["metrics"]["record_count"]) for item in benchmarks]
    search_contract = build_search_backend_contract(
        keywords=[normalized_keyword],
        limit=500,
        corpus_estimate={
            "benchmark_record_counts": record_counts,
            "case_db_total_rows": case_db_profile.get("total_profiled_rows", 0),
            "case_db_path": case_db_profile.get("path", ""),
        },
    )

    payload_without_hash: dict[str, object] = {
        "command": "large-case-readiness",
        "profile_version": LARGE_CASE_READINESS_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "item_numbers": list(LARGE_CASE_READINESS_ITEM_NUMBERS),
        "status": "internal-evidence-present" if not failed_checks else "needs-large-case-evidence",
        "commercial_grade_ready": False,
        "options": {
            "keyword": normalized_keyword,
            "max_query_p95_ms": float(max_query_p95_ms),
        },
        "summary": {
            "check_count": len(checks),
            "passed_check_count": len(checks) - len(failed_checks),
            "failed_check_count": len(failed_checks),
            "largest_benchmark_record_count": max(record_counts) if record_counts else 0,
            "benchmark_count": len(benchmarks),
            "case_db_attached": bool(case_db_profile.get("attached")),
            "case_db_search_diagnostics_ready": bool(
                ((case_db_profile.get("search_diagnostics") or {}).get("ready"))
            ),
            "commercial_blocker_count": len(large_case_commercial_blockers(record_counts)),
        },
        "checks": checks,
        "benchmarks": benchmarks,
        "case_db_profile": case_db_profile,
        "search_backend_contract": search_contract,
        "commercial_grade_blockers": large_case_commercial_blockers(record_counts),
        "mac_first_next_actions": large_case_next_actions(record_counts, case_db_profile),
    }
    payload = dict(payload_without_hash)
    payload["manifest_hash"] = stable_backend_sha256(payload_without_hash)
    if output is not None:
        write_result(payload, output.expanduser().resolve())
    return payload


def load_sqlite_fts_benchmark(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise LargeCaseReadinessError(f"SQLite FTS benchmark JSON not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise LargeCaseReadinessError(f"SQLite FTS benchmark JSON must be an object: {path}")
    if payload.get("profile_version") != SQLITE_FTS_BENCHMARK_VERSION:
        raise LargeCaseReadinessError(
            f"unsupported benchmark profile_version in {path}: {payload.get('profile_version')}"
        )
    metrics = payload.get("metrics")
    summary = payload.get("summary")
    if not isinstance(metrics, Mapping) or not isinstance(summary, Mapping):
        raise LargeCaseReadinessError(f"benchmark is missing metrics/summary: {path}")
    record_count = int(metrics.get("record_count") or 0)
    return {
        "path": str(path),
        "profile_version": str(payload.get("profile_version")),
        "record_count": record_count,
        "scale_label": scale_label(record_count),
        "metrics": {
            "record_count": record_count,
            "expected_hit_count": int(metrics.get("expected_hit_count") or 0),
            "returned_hit_count": int(metrics.get("returned_hit_count") or 0),
            "result_window_count": int(metrics.get("result_window_count") or 0),
            "truncated_by_result_window": bool(metrics.get("truncated_by_result_window")),
            "query_p50_seconds": float(metrics.get("query_p50_seconds") or 0),
            "query_p95_seconds": float(metrics.get("query_p95_seconds") or 0),
            "ingest_seconds": float(metrics.get("ingest_seconds") or 0),
            "records_per_second": float(metrics.get("records_per_second") or 0),
            "database_size_bytes": int(metrics.get("database_size_bytes") or 0),
        },
        "expected_counts_match": bool(summary.get("expected_counts_match")),
        "proof_manifest_hash": str(payload.get("proof_manifest_hash") or ""),
        "query_plan_hash": str(((payload.get("query_plan_profile") or {}).get("plan_hash")) or ""),
        "commercial_grade_ready": bool(summary.get("commercial_grade_ready")),
    }


def profile_case_db(path: Path, *, keyword: str = "needle") -> dict[str, object]:
    if not path.is_file():
        raise LargeCaseReadinessError(f"Case DB not found: {path}")
    with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        tables = [
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        indexes = [
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        fts_tables = [
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_fts' ORDER BY name"
            ).fetchall()
        ]
        table_counts = {
            table_name: safe_table_count(connection, table_name)
            for table_name in CASE_DB_PROFILE_TABLES
            if table_name in tables
        }
        pragmas = {
            "journal_mode": read_pragma(connection, "journal_mode"),
            "page_count": read_pragma(connection, "page_count"),
            "page_size": read_pragma(connection, "page_size"),
            "freelist_count": read_pragma(connection, "freelist_count"),
        }
        assessment = case_db_fts_optimization_assessment(connection)
        search_diagnostics = case_db_search_diagnostics(connection, keyword=keyword, fts_tables=fts_tables)

    profile_without_hash: dict[str, object] = {
        "attached": True,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "table_count": len(tables),
        "tables": tables,
        "index_count": len(indexes),
        "indexes": indexes,
        "fts_table_count": len(fts_tables),
        "fts_tables": fts_tables,
        "table_counts": table_counts,
        "total_profiled_rows": sum(table_counts.values()),
        "sqlite_pragmas": pragmas,
        "case_db_fts_optimization": assessment,
        "search_diagnostics": search_diagnostics,
    }
    profile = dict(profile_without_hash)
    profile["profile_hash"] = stable_backend_sha256(profile_without_hash)
    return profile


def safe_table_count(connection: sqlite3.Connection, table_name: str) -> int:
    try:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
    except sqlite3.DatabaseError:
        return -1
    return int(row["count"]) if row is not None else 0


def read_pragma(connection: sqlite3.Connection, pragma_name: str) -> object:
    try:
        row = connection.execute(f"PRAGMA {pragma_name}").fetchone()
    except sqlite3.DatabaseError as exc:
        return f"pragma-error:{exc}"
    if row is None:
        return None
    return row[0]


def case_db_search_diagnostics(
    connection: sqlite3.Connection,
    *,
    keyword: str,
    fts_tables: Sequence[str],
) -> dict[str, object]:
    normalized_keyword = keyword.strip() or "needle"
    table_profiles = [
        case_db_fts_table_search_profile(connection, table_name=table_name, keyword=normalized_keyword)
        for table_name in fts_tables
    ]
    ready = bool(table_profiles) and all(bool(item.get("query_plan_available")) for item in table_profiles)
    core: dict[str, object] = {
        "profile_version": "case-db-search-diagnostics-v1",
        "keyword": normalized_keyword,
        "ready": ready,
        "fts_table_count": len(table_profiles),
        "fts_tables": table_profiles,
        "diagnostic_scope": [
            "fts-row-count",
            "keyword-match-count",
            "explain-query-plan",
            "stable-table-profile-hash",
        ],
        "commercial_gap_ids": ["#66", "#74", "#78", "#79"],
        "commercial_claim_allowed": False,
        "blockers": [
            "attach-real-million-row-case-db-search-run-before-commercial-claim",
            "attach-ui-virtualization-evidence-for-large-result-review",
            "attach-trusted-tool-query-plan-or-known-answer-diff",
        ],
    }
    return {**core, "profile_hash": stable_backend_sha256(core)}


def case_db_fts_table_search_profile(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    keyword: str,
) -> dict[str, object]:
    quoted = quote_sqlite_identifier(table_name)
    errors: list[str] = []
    row_count = -1
    keyword_match_count = -1
    plan_details: list[str] = []
    try:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted}").fetchone()
        row_count = int(row["count"] if isinstance(row, sqlite3.Row) else row[0])
    except sqlite3.DatabaseError as exc:
        errors.append(f"row-count-error:{exc}")
    try:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted} WHERE {quoted} MATCH ?", (keyword,)).fetchone()
        keyword_match_count = int(row["count"] if isinstance(row, sqlite3.Row) else row[0])
    except sqlite3.DatabaseError as exc:
        errors.append(f"match-count-error:{exc}")
    try:
        rows = connection.execute(
            f"EXPLAIN QUERY PLAN SELECT rowid FROM {quoted} WHERE {quoted} MATCH ? LIMIT 100",
            (keyword,),
        ).fetchall()
        plan_details = [str(row["detail"] if isinstance(row, sqlite3.Row) else row[-1]) for row in rows]
    except sqlite3.DatabaseError as exc:
        errors.append(f"query-plan-error:{exc}")
    core: dict[str, object] = {
        "table": table_name,
        "row_count": row_count,
        "keyword_match_count": keyword_match_count,
        "query_plan_available": bool(plan_details) and not any(item.startswith("query-plan-error:") for item in errors),
        "query_plan_details": plan_details,
        "errors": errors,
    }
    return {**core, "table_profile_hash": stable_backend_sha256(core)}


def quote_sqlite_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def build_large_case_checks(
    *,
    benchmarks: Sequence[Mapping[str, object]],
    case_db_profile: Mapping[str, object],
    max_query_p95_ms: float,
) -> list[dict[str, object]]:
    record_counts = [int(item["record_count"]) for item in benchmarks]
    benchmark_p95_failures = [
        item
        for item in benchmarks
        if float(((item.get("metrics") or {}).get("query_p95_seconds")) or 0) * 1000 > max_query_p95_ms
    ]
    return [
        readiness_check(
            "sqlite-fts-benchmark-attached",
            bool(benchmarks),
            "At least one deterministic SQLite FTS benchmark JSON is attached.",
        ),
        readiness_check(
            "sqlite-fts-100k-or-higher",
            any(count >= 100_000 for count in record_counts),
            "A 100k+ row benchmark is attached for Mac-local smoke scale.",
        ),
        readiness_check(
            "sqlite-fts-1m-or-higher",
            any(count >= 1_000_000 for count in record_counts),
            "A 1M+ row benchmark is attached before million-row usability claims.",
        ),
        readiness_check(
            "sqlite-fts-10m-or-higher",
            any(count >= 10_000_000 for count in record_counts),
            "A 10M+ row benchmark is attached before commercial large-case claims.",
        ),
        readiness_check(
            "benchmark-known-answer-counts-match",
            bool(benchmarks) and all(bool(item.get("expected_counts_match")) for item in benchmarks),
            "Each benchmark returned the seeded known-answer hit count.",
        ),
        readiness_check(
            "benchmark-query-p95-under-threshold",
            bool(benchmarks) and not benchmark_p95_failures,
            f"Each benchmark query p95 is <= {max_query_p95_ms:g} ms.",
            evidence=[str(item.get("path")) for item in benchmark_p95_failures],
        ),
        readiness_check(
            "case-db-attached",
            bool(case_db_profile.get("attached")),
            "A Case DB is attached so schema, indexes, and FTS tables can be profiled.",
        ),
        readiness_check(
            "case-db-has-fts-tables",
            bool(case_db_profile.get("fts_table_count")),
            "Case DB exposes FTS tables for documents/artifacts.",
            evidence=list(case_db_profile.get("fts_tables") or []),
        ),
        readiness_check(
            "case-db-hot-path-indexes-present",
            int(case_db_profile.get("index_count") or 0) > 0,
            "Case DB has non-SQLite hot-path indexes.",
        ),
        readiness_check(
            "case-db-search-diagnostics-ready",
            bool(((case_db_profile.get("search_diagnostics") or {}).get("ready"))),
            "Case DB search diagnostics include FTS row counts, MATCH counts, and query plans.",
            evidence=[
                str(((case_db_profile.get("search_diagnostics") or {}).get("profile_hash")) or ""),
            ],
        ),
    ]


def readiness_check(
    check_id: str,
    passed: bool,
    description: str,
    *,
    evidence: Sequence[str] | None = None,
) -> dict[str, object]:
    return {
        "id": check_id,
        "passed": bool(passed),
        "description": description,
        "evidence": list(evidence or []),
    }


def large_case_commercial_blockers(record_counts: Sequence[int]) -> list[str]:
    blockers = [
        "attach-real-1tb-to-10tb-evidence-stress-log-with-memory-and-latency-profile",
        "attach-independent-validation-or-lab-reviewer-signoff-before-commercial-grade-claim",
        "attach-ui-browser-virtualization-evidence-for-massive-result-tables",
        "attach-cursor-api-regression-evidence-for-search-timeline-report-endpoints",
    ]
    if not any(count >= 1_000_000 for count in record_counts):
        blockers.insert(0, "attach-1m-record-sqlite-fts-benchmark-json")
    if not any(count >= 10_000_000 for count in record_counts):
        blockers.insert(0, "attach-10m-record-sqlite-fts-benchmark-json")
    return blockers


def large_case_next_actions(record_counts: Sequence[int], case_db_profile: Mapping[str, object]) -> list[str]:
    actions = []
    if not record_counts:
        actions.append("Run `rapidtriage sqlite-fts-benchmark --record-count 100000` and attach the JSON here.")
    if not any(count >= 1_000_000 for count in record_counts):
        actions.append("Run a 1M row SQLite FTS benchmark on the target Mac hardware.")
    if not any(count >= 10_000_000 for count in record_counts):
        actions.append("Run a 10M row SQLite FTS benchmark overnight before commercial large-case claims.")
    if not case_db_profile.get("attached"):
        actions.append("Attach a real Case DB with imported evidence to profile FTS/index/table counts.")
    elif not ((case_db_profile.get("search_diagnostics") or {}).get("ready")):
        actions.append("Regenerate the Case DB or investigate missing FTS query plans before large-case search claims.")
    actions.append("Repeat this report after every indexing/search change and commit the JSON as validation evidence.")
    return actions
