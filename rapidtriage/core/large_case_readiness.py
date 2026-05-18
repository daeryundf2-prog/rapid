from __future__ import annotations

import contextlib
import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Mapping, Sequence

from .benchmark import scale_label
from .benchmark_fts import SQLITE_FTS_BENCHMARK_VERSION
from .case_db import build_fts_query, case_db_fts_optimization_assessment, case_db_search_index_health
from .docs import write_result
from .large_case_controls import (
    build_duplicate_grouping_contract,
    build_hash_cache_persistence_contract,
    build_memory_cap_contract,
    build_parser_isolation_contract,
)
from .search_backend import build_search_backend_contract, stable_backend_sha256


LARGE_CASE_READINESS_VERSION = "large-case-readiness-v1"
LARGE_SCALE_PERFORMANCE_MATRIX_VERSION = "large-scale-performance-readiness-matrix-v1"
LARGE_CASE_READINESS_ITEM_NUMBERS = list(range(66, 81))
LARGE_SCALE_TARGET_RECORD_COUNTS = [100_000, 1_000_000, 10_000_000]
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
    memory_cap_bytes: int = 0,
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
    large_scale_matrix = build_large_scale_performance_matrix(
        benchmarks=benchmarks,
        case_db_profile=case_db_profile,
        checks=checks,
        max_query_p95_ms=max_query_p95_ms,
        memory_cap_bytes=memory_cap_bytes,
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
            "memory_cap_bytes": int(memory_cap_bytes or 0),
        },
        "summary": {
            "check_count": len(checks),
            "passed_check_count": len(checks) - len(failed_checks),
            "failed_check_count": len(failed_checks),
            "supported_backlog_items": list(LARGE_CASE_READINESS_ITEM_NUMBERS),
            "largest_benchmark_record_count": max(record_counts) if record_counts else 0,
            "benchmark_count": len(benchmarks),
            "case_db_attached": bool(case_db_profile.get("attached")),
            "case_db_search_diagnostics_ready": bool(
                ((case_db_profile.get("search_diagnostics") or {}).get("ready"))
            ),
            "case_db_search_index_healthy": bool(
                ((case_db_profile.get("search_index_health") or {}).get("ready_for_large_case_search"))
            ),
            "case_db_search_index_missing_rows": int(
                ((case_db_profile.get("search_index_health") or {}).get("summary") or {}).get("missing_index_rows")
                or 0
            ),
            "case_db_cursor_diagnostics_ready": bool(
                (
                    ((case_db_profile.get("search_diagnostics") or {}).get("cursor_diagnostics") or {}).get("ready")
                )
            ),
            "case_db_cursor_pagination_proven_tables": int(
                (
                    (
                        ((case_db_profile.get("search_diagnostics") or {}).get("cursor_diagnostics") or {}).get(
                            "summary"
                        )
                        or {}
                    ).get("pagination_proven_table_count")
                )
                or 0
            ),
            "case_db_cursor_diagnostics_hash": str(
                ((case_db_profile.get("search_diagnostics") or {}).get("cursor_diagnostics") or {}).get(
                    "profile_hash"
                )
                or ""
            ),
            "commercial_blocker_count": len(large_case_commercial_blockers(record_counts)),
            "large_scale_item_count": large_scale_matrix["summary"]["item_count"],
            "large_scale_usable_count": large_scale_matrix["summary"]["usable_count"],
            "large_scale_validated_count": large_scale_matrix["summary"]["validated_count"],
            "large_scale_external_evidence_required_count": large_scale_matrix["summary"][
                "external_evidence_required_count"
            ],
            "large_scale_matrix_hash": large_scale_matrix["matrix_hash"],
        },
        "checks": checks,
        "large_scale_performance_matrix": large_scale_matrix,
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
        case_ids = [
            str(row["case_id"])
            for row in connection.execute("SELECT case_id FROM case_record ORDER BY case_id").fetchall()
        ]
        search_index_health = case_db_search_index_health_summary(connection, case_ids=case_ids)

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
        "search_index_health": search_index_health,
    }
    profile = dict(profile_without_hash)
    profile["profile_hash"] = stable_backend_sha256(profile_without_hash)
    return profile


def case_db_search_index_health_summary(
    connection: sqlite3.Connection,
    *,
    case_ids: Sequence[str],
) -> dict[str, object]:
    profiles = [case_db_search_index_health(connection, case_id) for case_id in case_ids]
    missing_total = sum(int(((profile.get("summary") or {}).get("missing_index_rows")) or 0) for profile in profiles)
    orphan_total = sum(int(((profile.get("summary") or {}).get("orphan_fts_rows")) or 0) for profile in profiles)
    error_total = sum(int(((profile.get("summary") or {}).get("error_count")) or 0) for profile in profiles)
    unhealthy_case_ids = [str(profile.get("case_id") or "") for profile in profiles if profile.get("status") != "healthy"]
    core: dict[str, object] = {
        "profile_version": "case-db-search-index-health-summary-v1",
        "case_count": len(profiles),
        "status": "healthy" if profiles and not unhealthy_case_ids else "needs-rebuild",
        "ready_for_large_case_search": bool(profiles) and not unhealthy_case_ids,
        "summary": {
            "missing_index_rows": missing_total,
            "orphan_fts_rows": orphan_total,
            "error_count": error_total,
            "unhealthy_case_count": len(unhealthy_case_ids),
        },
        "case_ids": list(case_ids),
        "unhealthy_case_ids": unhealthy_case_ids,
        "case_profiles": profiles,
        "blockers": []
        if profiles and not unhealthy_case_ids
        else [
            "run rapidtriage case-db <db> --case-id <case> --rebuild-search-indexes for every unhealthy case",
            "do not make no-hit or absence claims from this Case DB until search_index_health is healthy",
        ],
    }
    return {**core, "profile_hash": stable_backend_sha256(core)}


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
    cursor_diagnostics = case_db_cursor_diagnostics(
        connection,
        keyword=normalized_keyword,
        fts_tables=fts_tables,
    )
    ready = (
        bool(table_profiles)
        and all(bool(item.get("query_plan_available")) for item in table_profiles)
        and bool(cursor_diagnostics.get("ready"))
    )
    core: dict[str, object] = {
        "profile_version": "case-db-search-diagnostics-v1",
        "keyword": normalized_keyword,
        "ready": ready,
        "fts_table_count": len(table_profiles),
        "fts_tables": table_profiles,
        "cursor_diagnostics": cursor_diagnostics,
        "diagnostic_scope": [
            "fts-row-count",
            "keyword-match-count",
            "explain-query-plan",
            "cursor-page-window-hashes",
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


def case_db_cursor_diagnostics(
    connection: sqlite3.Connection,
    *,
    keyword: str,
    fts_tables: Sequence[str],
    page_size: int = 1,
) -> dict[str, object]:
    normalized_keyword = keyword.strip() or "needle"
    normalized_page_size = max(1, min(100, int(page_size)))
    table_profiles = [
        case_db_fts_table_cursor_profile(
            connection,
            table_name=table_name,
            keyword=normalized_keyword,
            page_size=normalized_page_size,
        )
        for table_name in fts_tables
    ]
    pagination_proven_count = sum(bool(item.get("pagination_proven")) for item in table_profiles)
    errored_count = sum(1 for item in table_profiles if item.get("errors"))
    ready = bool(table_profiles) and all(bool(item.get("cursor_contract_ready")) for item in table_profiles)
    core: dict[str, object] = {
        "profile_version": "case-db-cursor-diagnostics-v1",
        "keyword": normalized_keyword,
        "page_size": normalized_page_size,
        "ready": ready,
        "summary": {
            "fts_table_count": len(table_profiles),
            "cursor_contract_ready_table_count": sum(
                bool(item.get("cursor_contract_ready")) for item in table_profiles
            ),
            "pagination_proven_table_count": pagination_proven_count,
            "errored_table_count": errored_count,
        },
        "tables": table_profiles,
        "diagnostic_scope": [
            "deterministic-rowid-order",
            "page-one-row-hash",
            "page-two-row-hash-when-available",
            "next-offset-hash",
            "non-overlap-proof",
        ],
        "commercial_gap_ids": ["#78", "#79"],
        "commercial_claim_allowed": False,
        "blockers": []
        if pagination_proven_count
        else [
            "seed-at-least-two-matching-case-db-rows-to-prove-next-cursor-pagination",
            "attach-browser-row-window-evidence-before-ui-virtualization-claims",
        ],
    }
    return {**core, "profile_hash": stable_backend_sha256(core)}


def case_db_fts_table_cursor_profile(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    keyword: str,
    page_size: int,
) -> dict[str, object]:
    quoted = quote_sqlite_identifier(table_name)
    query = build_fts_query([keyword])
    errors: list[str] = []
    page_one_rowids: list[int] = []
    page_two_rowids: list[int] = []
    has_more = False
    next_offset = 0

    def read_page(offset: int) -> list[int]:
        rows = connection.execute(
            f"""
            SELECT rowid
            FROM {quoted}
            WHERE {quoted} MATCH ?
            ORDER BY rowid ASC
            LIMIT ?
            OFFSET ?
            """,
            (query, page_size + 1, offset),
        ).fetchall()
        return [int(row["rowid"] if isinstance(row, sqlite3.Row) else row[0]) for row in rows]

    try:
        first_window = read_page(0)
        page_one_rowids = first_window[:page_size]
        has_more = len(first_window) > page_size
        if has_more:
            next_offset = page_size
            second_window = read_page(next_offset)
            page_two_rowids = second_window[:page_size]
    except sqlite3.DatabaseError as exc:
        errors.append(f"cursor-page-error:{exc}")

    scope = {
        "table": table_name,
        "keyword": keyword,
        "page_size": page_size,
        "ordering": "rowid-ascending",
    }
    page_one_hash = stable_backend_sha256(
        {"scope": scope, "offset": 0, "rowids": page_one_rowids}
    )
    page_two_hash = (
        stable_backend_sha256({"scope": scope, "offset": next_offset, "rowids": page_two_rowids})
        if has_more
        else ""
    )
    non_overlapping_pages = not (set(page_one_rowids) & set(page_two_rowids))
    core: dict[str, object] = {
        "table": table_name,
        "keyword": keyword,
        "page_size": page_size,
        "ordering": "rowid-ascending",
        "cursor_contract_ready": not errors,
        "pagination_proven": bool(has_more and page_two_rowids and non_overlapping_pages),
        "has_more": has_more,
        "next_offset": next_offset if has_more else None,
        "next_offset_hash": stable_backend_sha256({"scope": scope, "offset": next_offset}) if has_more else "",
        "page_one_rowids": page_one_rowids,
        "page_two_rowids": page_two_rowids,
        "page_one_hash": page_one_hash,
        "page_two_hash": page_two_hash,
        "non_overlapping_pages": non_overlapping_pages,
        "rowid_sample_count": len(page_one_rowids) + len(page_two_rowids),
        "errors": errors,
    }
    return {**core, "cursor_profile_hash": stable_backend_sha256(core)}


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
        readiness_check(
            "case-db-cursor-diagnostics-ready",
            bool(
                (((case_db_profile.get("search_diagnostics") or {}).get("cursor_diagnostics") or {}).get("ready"))
            ),
            "Case DB cursor diagnostics emit stable page-window hashes and next-offset evidence.",
            evidence=[
                str(
                    ((case_db_profile.get("search_diagnostics") or {}).get("cursor_diagnostics") or {}).get(
                        "profile_hash"
                    )
                    or ""
                ),
            ],
        ),
        readiness_check(
            "case-db-search-index-healthy",
            bool(((case_db_profile.get("search_index_health") or {}).get("ready_for_large_case_search"))),
            "Every Case DB search index is complete enough for no-hit/absence search claims.",
            evidence=[
                str(((case_db_profile.get("search_index_health") or {}).get("profile_hash")) or ""),
            ],
        ),
    ]


def build_large_scale_performance_matrix(
    *,
    benchmarks: Sequence[Mapping[str, object]],
    case_db_profile: Mapping[str, object],
    checks: Sequence[Mapping[str, object]],
    max_query_p95_ms: float,
    memory_cap_bytes: int = 0,
) -> dict[str, object]:
    check_passed = {str(item.get("id")): bool(item.get("passed")) for item in checks}
    record_counts = [int(item.get("record_count") or 0) for item in benchmarks]
    covered_targets = [
        {
            "label": scale_label(target),
            "target_record_count": target,
            "covered": any(count >= target for count in record_counts),
        }
        for target in LARGE_SCALE_TARGET_RECORD_COUNTS
    ]
    fts_assessment = (
        case_db_profile.get("case_db_fts_optimization")
        if isinstance(case_db_profile.get("case_db_fts_optimization"), Mapping)
        else {}
    )
    search_diagnostics = (
        case_db_profile.get("search_diagnostics")
        if isinstance(case_db_profile.get("search_diagnostics"), Mapping)
        else {}
    )
    cursor_diagnostics = (
        search_diagnostics.get("cursor_diagnostics")
        if isinstance(search_diagnostics.get("cursor_diagnostics"), Mapping)
        else {}
    )
    search_index_health = (
        case_db_profile.get("search_index_health")
        if isinstance(case_db_profile.get("search_index_health"), Mapping)
        else {}
    )
    hash_cache_contract = build_hash_cache_persistence_contract()
    duplicate_contract = build_duplicate_grouping_contract()
    parser_isolation_contract = build_parser_isolation_contract()
    memory_cap_contract = build_memory_cap_contract(requested_cap_bytes=memory_cap_bytes)

    benchmark_validated = (
        check_passed.get("sqlite-fts-benchmark-attached", False)
        and check_passed.get("benchmark-known-answer-counts-match", False)
        and check_passed.get("benchmark-query-p95-under-threshold", False)
    )
    case_db_search_ready = bool(search_diagnostics.get("ready"))
    cursor_ready = bool(cursor_diagnostics.get("ready"))
    search_index_ready = bool(search_index_health.get("ready_for_large_case_search"))
    fts_ready = bool(fts_assessment.get("ready_for_large_case_search") or case_db_search_ready)

    items = [
        large_scale_performance_item_row(
            66,
            "100k/1M/10M benchmark gate",
            implemented_controls=[
                "sqlite-fts-benchmark command",
                "deterministic known-answer hit count",
                "query p50/p95 latency samples",
                "scale target coverage matrix",
            ],
            validation_evidence=[
                f"benchmark_count={len(benchmarks)}",
                f"largest_benchmark_record_count={max(record_counts) if record_counts else 0}",
                f"max_query_p95_ms={float(max_query_p95_ms):g}",
            ],
            blockers=missing_large_scale_target_blockers(record_counts)
            + ["representative-release-hardware-benchmark-matrix-required"],
            usable=bool(benchmarks),
            validated=benchmark_validated,
        ),
        large_scale_performance_item_row(
            67,
            "1TB-10TB stress runbook and evidence slots",
            implemented_controls=[
                "stress-plan command",
                "hardware-scale evidence manifest",
                "resource cap and failure-threshold checklist",
            ],
            validation_evidence=["runbook-generation-supported"],
            blockers=[
                "attach-actual-1tb-5tb-10tb-run-logs",
                "attach-memory-p95-latency-and-failure-threshold-telemetry",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            68,
            "Incremental indexing and stage reuse",
            implemented_controls=[
                "case search index health gate",
                "resume-aware workflow outputs",
                "hash/fingerprint invalidation contract",
            ],
            validation_evidence=[
                f"search_index_health={search_index_health.get('status') or 'not-attached'}",
                str(search_index_health.get("profile_hash") or ""),
            ],
            blockers=[
                "large-real-case-stage-reuse-benchmark-required",
                "content-hash-complete-incremental-indexing-diff-required",
            ],
            usable=True,
            validated=search_index_ready,
        ),
        large_scale_performance_item_row(
            69,
            "Background job queue",
            implemented_controls=[
                "RunJobStore local queue",
                "persisted job transition log",
                "job step state model",
            ],
            validation_evidence=["/api/runs submit/status route family", "job_queue_assessment emitted per run"],
            blockers=[
                "parser-level-progress-percent-under-load-required",
                "distributed-or-multi-worker-transition-log-diff-required",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            70,
            "Checkpoint and resume",
            implemented_controls=[
                "run --resume option",
                "stage output reuse policy",
                "E01/hash checkpoint options",
            ],
            validation_evidence=["checkpoint-capable commands are exposed"],
            blockers=[
                "mid-parser-resume-fixture-required",
                "failed-stage-only-resume-replay-log-required",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            71,
            "Parser crash isolation",
            implemented_controls=[
                "local crash report writer",
                "redacted crash export bundle",
                "parser isolation contract",
            ],
            validation_evidence=[
                parser_isolation_contract["contract_hash"],
                "crash reports are local-only and exportable",
            ],
            blockers=list(parser_isolation_contract["commercial_blockers"]),
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            72,
            "Memory cap enforcement",
            implemented_controls=[
                "RunRequest.memory_cap_bytes",
                "memory-cap contract",
                "stage telemetry expectation",
            ],
            validation_evidence=[
                memory_cap_contract["contract_hash"],
                f"requested_cap_bytes={int(memory_cap_bytes or 0)}",
            ],
            blockers=list(memory_cap_contract["commercial_blockers"]),
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            73,
            "Preview sandboxing",
            implemented_controls=[
                "bounded source preview",
                "viewer workflow validation",
                "active-content blocking policy",
            ],
            validation_evidence=["source viewer routes require bounded preview/hex/table modes"],
            blockers=[
                "malicious-document-preview-corpus-required",
                "renderer-sandbox-escape-regression-required",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            74,
            "Large SQLite and FTS optimization",
            implemented_controls=[
                "SQLite FTS benchmark",
                "Case DB FTS table profile",
                "EXPLAIN QUERY PLAN capture",
                "search index health gate",
            ],
            validation_evidence=[
                f"fts_ready={fts_ready}",
                str(search_diagnostics.get("profile_hash") or ""),
            ],
            blockers=[
                "trusted-query-plan-threshold-diff-required",
                "million-row-real-case-latency-benchmark-required",
            ],
            usable=bool(benchmarks) or bool(case_db_profile.get("attached")),
            validated=benchmark_validated and fts_ready,
        ),
        large_scale_performance_item_row(
            75,
            "Parallel parser scheduler",
            implemented_controls=[
                "bounded local worker pool",
                "deterministic job transition ordering",
                "parser stage status model",
            ],
            validation_evidence=["ThreadPoolExecutor-backed run queue"],
            blockers=[
                "cpu-io-quota-telemetry-required",
                "deterministic-output-order-under-parallel-parser-load-required",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            76,
            "File hash cache",
            implemented_controls=[
                "hash cache persistence contract",
                "size/mtime/inode/device invalidation fields",
                "path-disclosure-minimized snapshot",
            ],
            validation_evidence=[hash_cache_contract["contract_hash"]],
            blockers=list(hash_cache_contract["commercial_blockers"]),
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            77,
            "Duplicate file/content detection",
            implemented_controls=[
                "exact hash baseline",
                "duplicate grouping contract",
                "review collapse state requirements",
            ],
            validation_evidence=[duplicate_contract["contract_hash"]],
            blockers=list(duplicate_contract["commercial_blockers"]),
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            78,
            "Artifact pagination and cursor API",
            implemented_controls=[
                "case-db cursor diagnostics",
                "stable page window hashes",
                "next-offset evidence",
            ],
            validation_evidence=[
                f"cursor_ready={cursor_ready}",
                str(cursor_diagnostics.get("profile_hash") or ""),
            ],
            blockers=[
                "cursor-api-regression-suite-for-search-timeline-report-required",
                "browser-pagination-e2e-trace-required",
            ],
            usable=True,
            validated=cursor_ready,
        ),
        large_scale_performance_item_row(
            79,
            "UI virtualization for massive result tables",
            implemented_controls=[
                "/api/workbench/large-result-evidence",
                "bounded DOM row window contract",
                "keyboard window navigation contract",
            ],
            validation_evidence=["large-result-ui-evidence-v1 endpoint available"],
            blockers=[
                "actual-browser-100k-run-required",
                "memory-profile-and-p95-latency-required",
            ],
            usable=True,
            validated=False,
        ),
        large_scale_performance_item_row(
            80,
            "Long-running job cancellation and retry",
            implemented_controls=[
                "run cancellation flag",
                "retry lineage profile",
                "partial output policy",
            ],
            validation_evidence=["cancellation_retry_assessment emitted per run"],
            blockers=[
                "cooperative-cancellation-load-validation-required",
                "idempotent-retry-output-validation-required",
            ],
            usable=True,
            validated=False,
        ),
    ]

    commercial_blockers = sorted(
        {blocker for item in items for blocker in item["commercial_grade_blockers"]}
    )
    core: dict[str, object] = {
        "profile_version": LARGE_SCALE_PERFORMANCE_MATRIX_VERSION,
        "item_numbers": list(LARGE_CASE_READINESS_ITEM_NUMBERS),
        "scale_targets": covered_targets,
        "summary": {
            "item_count": len(items),
            "usable_count": sum(bool(item["usable"]) for item in items),
            "validated_count": sum(bool(item["validated"]) for item in items),
            "external_evidence_required_count": sum(
                bool(item["external_evidence_required"]) for item in items
            ),
            "commercial_blocker_count": len(commercial_blockers),
            "covered_scale_target_count": sum(bool(item["covered"]) for item in covered_targets),
            "case_db_attached": bool(case_db_profile.get("attached")),
            "case_db_cursor_ready": cursor_ready,
            "case_db_search_index_ready": search_index_ready,
        },
        "items": items,
        "commercial_grade_blockers": commercial_blockers,
        "reportability_decision": {
            "commercial_claim_allowed": False,
            "decision": "internal-controls-present-but-external-scale-evidence-required",
            "required_before_claim": [
                "attach 1M and 10M benchmark JSON generated on target hardware",
                "attach 1TB/5TB/10TB stress logs with memory and p95 latency telemetry",
                "attach browser virtualization trace and cursor API regression evidence",
            ],
        },
    }
    return {**core, "matrix_hash": stable_backend_sha256(core)}


def large_scale_performance_item_row(
    item_number: int,
    title: str,
    *,
    implemented_controls: Sequence[str],
    validation_evidence: Sequence[str],
    blockers: Sequence[str],
    usable: bool,
    validated: bool,
) -> dict[str, object]:
    commercial_blockers = [str(item) for item in blockers if str(item)]
    external_evidence_required = bool(commercial_blockers)
    if validated and not external_evidence_required:
        status = "validated"
    elif validated:
        status = "internal-validated-commercial-evidence-required"
    elif usable:
        status = "usable-internal-controls-external-evidence-required"
    else:
        status = "not-usable-yet"
    row_core: dict[str, object] = {
        "item_number": int(item_number),
        "gap_id": f"#{int(item_number)}",
        "title": title,
        "status": status,
        "usable": bool(usable),
        "validated": bool(validated),
        "external_evidence_required": external_evidence_required,
        "commercial_grade_ready": bool(validated and not external_evidence_required),
        "implemented_controls": list(implemented_controls),
        "validation_evidence": [str(item) for item in validation_evidence if str(item)],
        "commercial_grade_blockers": commercial_blockers,
    }
    return {**row_core, "row_hash": stable_backend_sha256(row_core)}


def missing_large_scale_target_blockers(record_counts: Sequence[int]) -> list[str]:
    blockers = []
    for target in LARGE_SCALE_TARGET_RECORD_COUNTS:
        if not any(int(count) >= target for count in record_counts):
            blockers.append(f"attach-{scale_label(target).lower()}-record-sqlite-fts-benchmark-json")
    return blockers


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
    elif not ((case_db_profile.get("search_index_health") or {}).get("ready_for_large_case_search")):
        actions.append("Run `rapidtriage case-db <db> --case-id <case> --rebuild-search-indexes` for unhealthy cases.")
    actions.append("Repeat this report after every indexing/search change and commit the JSON as validation evidence.")
    return actions
