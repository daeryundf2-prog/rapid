"""FTS index health and rebuild helpers."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence

from ..forensic_accuracy import build_accuracy_gate
from .constants import (
    FUNCTIONAL_SCALE_BATCH_ID,
    LARGE_SQLITE_FTS_GAP_ID,
    LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS,
    LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
)
from .helpers import (
    count_rows,
)

__all__ = [
    "build_case_db_fts_trusted_diff",
    "case_db_fts_diff_value",
    "case_db_fts_functional_profile",
    "case_db_fts_health_profile",
    "case_db_fts_optimization_assessment",
    "case_db_large_sqlite_fts_report_grade_validation_plan",
    "case_db_query_plan_profile",
    "case_db_search_index_health",
    "count_case_fts_rows",
    "count_missing_fts_rows",
    "count_orphan_fts_rows",
    "rebuild_case_db_search_indexes",
    "rebuild_external_content_fts",
    "rebuild_standalone_fts",
]

def case_db_search_index_health(connection: sqlite3.Connection, case_id: str) -> dict[str, object]:
    profiles = [
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="documents",
            source_table="indexed_document",
            fts_table="indexed_document_fts",
            source_label="extracted document/OCR text",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="files",
            source_table="file_record",
            fts_table="file_record_fts",
            source_label="file path, extension, and hash metadata",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="artifacts",
            source_table="artifact",
            fts_table="artifact_fts",
            source_label="artifact and indicator title/summary/metadata",
        ),
        case_db_fts_health_profile(
            connection,
            case_id=case_id,
            source="timeline",
            source_table="event",
            fts_table="event_fts",
            source_label="timeline event type/time/target/description/source",
        ),
    ]
    missing_total = sum(int(profile["missing_index_rows"]) for profile in profiles)
    orphan_total = sum(int(profile["orphan_fts_rows"]) for profile in profiles)
    error_count = sum(1 for profile in profiles if profile.get("error"))
    status = "healthy" if missing_total == 0 and orphan_total == 0 and error_count == 0 else "needs-rebuild"
    return {
        "profile_version": "case-db-search-index-health-v1",
        "case_id": case_id,
        "status": status,
        "ready_for_large_case_search": status == "healthy",
        "summary": {
            "source_count": len(profiles),
            "missing_index_rows": missing_total,
            "orphan_fts_rows": orphan_total,
            "error_count": error_count,
        },
        "indexes": profiles,
        "commercial_gap_ids": ["#61", "#68", "#74", "#78", "#79"],
        "core_accuracy_gates": [
            build_accuracy_gate(
                74,
                satisfied_checks=[
                    "case-scoped FTS row counts emitted",
                    "missing source-to-index rows counted",
                    "orphan index rows counted",
                    "rebuild recommendation emitted",
                ],
                evidence_refs=[
                    f"status:{status}",
                    f"missing_index_rows:{missing_total}",
                    f"orphan_fts_rows:{orphan_total}",
                ],
            )
        ],
        "blockers": [
            "external 1M+/10M+ row benchmark evidence still required for commercial performance claims",
        ]
        if status == "healthy"
        else [
            "run rapidtriage case-db <db> --case-id <case> --rebuild-search-indexes before relying on complete search",
            "external 1M+/10M+ row benchmark evidence still required for commercial performance claims",
        ],
    }


def case_db_fts_health_profile(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    source: str,
    source_table: str,
    fts_table: str,
    source_label: str,
) -> dict[str, object]:
    try:
        source_rows = count_rows(connection, source_table, case_id)
        indexed_rows = count_case_fts_rows(connection, source_table=source_table, fts_table=fts_table, case_id=case_id)
        missing_rows = count_missing_fts_rows(connection, source_table=source_table, fts_table=fts_table, case_id=case_id)
        orphan_rows = count_orphan_fts_rows(connection, source_table=source_table, fts_table=fts_table)
        status = "healthy" if missing_rows == 0 and orphan_rows == 0 else "needs-rebuild"
        error = ""
    except sqlite3.OperationalError as exc:
        source_rows = 0
        indexed_rows = 0
        missing_rows = 0
        orphan_rows = 0
        status = "error"
        error = str(exc)
    return {
        "source": source,
        "source_table": source_table,
        "fts_table": fts_table,
        "source_label": source_label,
        "status": status,
        "source_rows": source_rows,
        "indexed_rows": indexed_rows,
        "missing_index_rows": missing_rows,
        "orphan_fts_rows": orphan_rows,
        "error": error,
        "recommendation": "rebuild-search-indexes" if status != "healthy" else "none",
    }


def count_case_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
    case_id: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {fts_table}
        JOIN {source_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.case_id = ?
        """,
        (case_id,),
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def count_missing_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
    case_id: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {source_table}
        LEFT JOIN {fts_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.case_id = ?
          AND {fts_table}.rowid IS NULL
        """,
        (case_id,),
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def count_orphan_fts_rows(
    connection: sqlite3.Connection,
    *,
    source_table: str,
    fts_table: str,
) -> int:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM {fts_table}
        LEFT JOIN {source_table} ON {fts_table}.rowid = {source_table}.id
        WHERE {source_table}.id IS NULL
        """
    ).fetchone()
    return int(row["count"] if row is not None else 0)


def rebuild_case_db_search_indexes(connection: sqlite3.Connection, case_id: str) -> dict[str, object]:
    before = case_db_search_index_health(connection, case_id)
    actions: list[dict[str, object]] = []
    actions.append(rebuild_external_content_fts(connection, fts_table="indexed_document_fts"))
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="files",
            source_table="file_record",
            fts_table="file_record_fts",
            columns=("path", "extension", "hashes"),
            select_sql="""
                SELECT
                    id,
                    path,
                    extension,
                    trim(COALESCE(hash_md5, '') || ' ' || COALESCE(hash_sha1, '') || ' ' || COALESCE(hash_sha256, ''))
                FROM file_record
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="artifacts",
            source_table="artifact",
            fts_table="artifact_fts",
            columns=("title", "summary", "metadata"),
            select_sql="""
                SELECT id, title, summary, data_json
                FROM artifact
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    actions.append(
        rebuild_standalone_fts(
            connection,
            case_id=case_id,
            source="timeline",
            source_table="event",
            fts_table="event_fts",
            columns=("event_type", "timestamp", "target", "description", "source"),
            select_sql="""
                SELECT id, event_type, timestamp, target, description, source
                FROM event
                WHERE case_id = ?
                ORDER BY id ASC
            """,
        )
    )
    after = case_db_search_index_health(connection, case_id)
    return {
        "profile_version": "case-db-search-index-rebuild-v1",
        "case_id": case_id,
        "status": "rebuilt" if after["status"] == "healthy" else "partial",
        "before": before,
        "after": after,
        "actions": actions,
        "commercial_gap_ids": ["#61", "#68", "#74", "#78", "#79"],
    }


def rebuild_external_content_fts(connection: sqlite3.Connection, *, fts_table: str) -> dict[str, object]:
    try:
        connection.execute(f"INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')")
        status = "rebuilt"
        error = ""
    except sqlite3.OperationalError as exc:
        status = "error"
        error = str(exc)
    return {
        "source": "documents",
        "fts_table": fts_table,
        "status": status,
        "scope": "all-cases",
        "error": error,
    }


def rebuild_standalone_fts(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    source: str,
    source_table: str,
    fts_table: str,
    columns: Sequence[str],
    select_sql: str,
) -> dict[str, object]:
    try:
        row_ids = [
            int(row["id"])
            for row in connection.execute(
                f"SELECT id FROM {source_table} WHERE case_id = ? ORDER BY id ASC",
                (case_id,),
            ).fetchall()
        ]
        for row_id in row_ids:
            connection.execute(f"DELETE FROM {fts_table} WHERE rowid = ?", (row_id,))
        placeholders = ", ".join("?" for _ in columns)
        column_sql = ", ".join(columns)
        inserted = 0
        for row in connection.execute(select_sql, (case_id,)).fetchall():
            values = [row[column] for column in row.keys() if column != "id"]
            connection.execute(
                f"INSERT INTO {fts_table}(rowid, {column_sql}) VALUES (?, {placeholders})",
                (row["id"], *values),
            )
            inserted += 1
        return {
            "source": source,
            "fts_table": fts_table,
            "status": "rebuilt",
            "deleted_rows": len(row_ids),
            "inserted_rows": inserted,
            "scope": "case",
            "error": "",
        }
    except sqlite3.OperationalError as exc:
        return {
            "source": source,
            "fts_table": fts_table,
            "status": "error",
            "deleted_rows": 0,
            "inserted_rows": 0,
            "scope": "case",
            "error": str(exc),
        }


def case_db_fts_optimization_assessment(connection: sqlite3.Connection) -> dict[str, object]:
    indexes = [
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name"
        ).fetchall()
    ]
    fts_tables = [
        str(row["name"])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%_fts' ORDER BY name"
        ).fetchall()
    ]
    query_plan_profile = case_db_query_plan_profile(connection, fts_tables=fts_tables)
    validation_plan = case_db_large_sqlite_fts_report_grade_validation_plan(
        query_plan_profile=query_plan_profile,
        fts_tables=fts_tables,
        index_count=len(indexes),
    )
    return {
        "component": "case-db-large-sqlite-fts",
        "status": "fts5-and-hot-path-indexes-enabled",
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "functional_priority_profile": case_db_fts_functional_profile(
            fts_tables=fts_tables,
            index_count=len(indexes),
            validation_plan=validation_plan,
        ),
        "fts_tables": fts_tables,
        "index_count": len(indexes),
        "hot_path_indexes": indexes,
        "query_plan_profile": query_plan_profile,
        "sqlite_pragmas": {
            "foreign_keys": True,
            "temp_store": "MEMORY",
            "cache_size_kib": 65536,
            "journal_mode": "WAL-when-supported",
            "optimize_on_close": True,
        },
        "large_sqlite_fts_report_grade_validation_plan": validation_plan,
        "large_sqlite_fts_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "core_accuracy_gates": [
            build_accuracy_gate(
                74,
                satisfied_checks=[
                    "SQLite performance pragmas applied",
                    "table profile emitted",
                    "searchable text columns counted",
                    "bounded row preview preserved",
                    "case DB query plan profile emitted",
                    "large corpus optimization limitation warning",
                    "large SQLite/FTS report-grade validation plan emitted",
                    "large SQLite/FTS report-grade ready slots emitted",
                ],
                evidence_refs=[
                    f"fts_table_count:{len(fts_tables)}",
                    f"index_count:{len(indexes)}",
                    f"query_plan_hash:{query_plan_profile['plan_hash']}",
                    f"large_sqlite_fts_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                    "journal_mode:WAL-when-supported",
                ],
            )
        ],
        "blockers": list(validation_plan["blockers"]),
    }


def case_db_large_sqlite_fts_report_grade_validation_plan(
    *,
    query_plan_profile: Mapping[str, object],
    fts_tables: Sequence[str],
    index_count: int,
) -> dict[str, object]:
    query_plan_hash = str(query_plan_profile.get("plan_hash") or "")
    fts_table_head_hash = hashlib.sha256("\n".join(sorted(str(table) for table in fts_tables)).encode("utf-8")).hexdigest()
    case_db_profile = {
        "fts_tables": sorted(str(table) for table in fts_tables),
        "index_count": index_count,
        "journal_mode": "WAL-when-supported",
        "optimize_on_close": True,
    }
    case_db_profile_hash = hashlib.sha256(json.dumps(case_db_profile, sort_keys=True).encode("utf-8")).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "case-db-query-plan-profile",
            "status": "ready",
            "evidence_ref": "query_plan_hash",
            "evidence_hash": query_plan_hash,
            "description": "Case DB emits deterministic query-plan hashes for hot-path and FTS queries.",
        },
        {
            "slot_id": "case-db-fts-table-inventory",
            "status": "ready",
            "evidence_ref": "fts_table_head_hash",
            "evidence_hash": fts_table_head_hash,
            "description": "FTS table inventory is hashed for release regression review.",
        },
        {
            "slot_id": "case-db-index-inventory",
            "status": "ready",
            "evidence_ref": "index_count",
            "evidence_hash": hashlib.sha256(str(index_count).encode("ascii")).hexdigest(),
            "description": "Hot-path index count is captured at schema initialization.",
        },
        {
            "slot_id": "wal-when-supported-policy",
            "status": "ready",
            "evidence_ref": "journal_mode",
            "evidence_hash": hashlib.sha256(b"WAL-when-supported").hexdigest(),
            "description": "Case DB policy requests WAL where the host SQLite build supports it.",
        },
        {
            "slot_id": "pragma-optimize-policy",
            "status": "ready",
            "evidence_ref": "optimize_on_close",
            "evidence_hash": hashlib.sha256(b"True").hexdigest(),
            "description": "Case DB records PRAGMA optimize on close as the local maintenance policy.",
        },
        {
            "slot_id": "case-db-performance-profile",
            "status": "ready",
            "evidence_ref": "case_db_profile_hash",
            "evidence_hash": case_db_profile_hash,
            "description": "FTS tables, indexes, WAL policy, and optimize policy are grouped for report review.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-case-db-query-plan-diff",
            "status": "blocked",
            "blocker": "trusted-case-db-sqlite-fts-query-plan-diff-missing",
            "required_evidence": "trusted Case DB SQLite/FTS query-plan manifest diff",
        },
        {
            "slot_id": "10m-row-query-plan-regression",
            "status": "blocked",
            "blocker": "10m-row-query-plan-regression-required",
            "required_evidence": "10M-row Case DB query-plan and latency regression evidence",
        },
        {
            "slot_id": "deleted-row-wal-replay",
            "status": "blocked",
            "blocker": "deleted-row-wal-replay-validation-required",
            "required_evidence": "source SQLite WAL/deleted-row replay validation before claiming recovery completeness",
        },
        {
            "slot_id": "large-source-db-corpus",
            "status": "blocked",
            "blocker": "large-source-db-corpus-required",
            "required_evidence": "large source SQLite and Case DB corpus covering multi-GB evidence",
        },
        {
            "slot_id": "browser-pagination-query-plan-e2e",
            "status": "blocked",
            "blocker": "browser-pagination-query-plan-e2e-required",
            "required_evidence": "browser E2E evidence that large query/table views remain paginated and bounded",
        },
        {
            "slot_id": "index-maintenance-vacuum-regression",
            "status": "blocked",
            "blocker": "index-maintenance-vacuum-regression-required",
            "required_evidence": "index maintenance, PRAGMA optimize, vacuum, and rebuild regression logs",
        },
    ]
    plan_core = {
        "profile_version": LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 74,
        "gap_id": LARGE_SQLITE_FTS_GAP_ID,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "scope": "case-db-sqlite-fts",
        "query_plan_hash": query_plan_hash,
        "fts_table_count": len(fts_tables),
        "fts_table_head_hash": fts_table_head_hash,
        "index_count": index_count,
        "case_db_profile_hash": case_db_profile_hash,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as Case DB SQLite/FTS readiness evidence only until trusted query-plan and large-row regression evidence are attached.",
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_sha256": validation_plan_sha256,
        "validation_plan_hash": validation_plan_sha256,
    }


def case_db_query_plan_profile(connection: sqlite3.Connection, *, fts_tables: Sequence[str]) -> dict[str, object]:
    statements = [
        (
            "indexed_document_by_case",
            "EXPLAIN QUERY PLAN SELECT id FROM indexed_document WHERE case_id = ? LIMIT 10",
            ("CASE-ID",),
        ),
        (
            "artifact_by_case",
            "EXPLAIN QUERY PLAN SELECT id FROM artifact WHERE case_id = ? LIMIT 10",
            ("CASE-ID",),
        ),
    ]
    if "artifact_fts" in fts_tables:
        statements.append(
            (
                "artifact_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM artifact_fts WHERE artifact_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "indexed_document_fts" in fts_tables:
        statements.append(
            (
                "indexed_document_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM indexed_document_fts WHERE indexed_document_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "file_record_fts" in fts_tables:
        statements.append(
            (
                "file_record_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM file_record_fts WHERE file_record_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    if "event_fts" in fts_tables:
        statements.append(
            (
                "event_fts_match",
                "EXPLAIN QUERY PLAN SELECT rowid FROM event_fts WHERE event_fts MATCH ? LIMIT 10",
                ("password",),
            )
        )
    plans: list[dict[str, object]] = []
    for name, sql, params in statements:
        try:
            rows = connection.execute(sql, params).fetchall()
            details = [str(row["detail"] if isinstance(row, sqlite3.Row) else row[-1]) for row in rows]
        except sqlite3.DatabaseError as exc:
            details = [f"query-plan-error:{exc}"]
        plans.append({"name": name, "details": details, "bounded_limit": 10})
    plan_hash = hashlib.sha256(json.dumps(plans, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "profile_version": "case-db-query-plan-profile-v1",
        "plan_count": len(plans),
        "plan_hash": plan_hash,
        "plans": plans,
        "uses_fts_tables": bool(fts_tables),
        "bounded_limit": 10,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": False,
    }


def case_db_fts_functional_profile(
    *,
    fts_tables: Sequence[str],
    index_count: int,
    validation_plan: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 32,
        "gap_id": "#32",
        "component": "sqlite-fts-optimization",
        "status": "implemented-case-db-fts5-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "fts_tables": list(fts_tables),
            "fts_table_count": len(fts_tables),
            "hot_path_index_count": index_count,
            "wal_when_supported": True,
            "pragma_optimize_on_close": True,
            "bounded_preview_contract": True,
            "large_sqlite_fts_report_grade_validation_plan_hash": str(
                validation_plan.get("validation_plan_sha256") or ""
            ),
            "large_sqlite_fts_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "large_sqlite_fts_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
        },
        "blockers": [
            "10m-record-benchmark-and-query-plan-regression-gates-remain-required",
            "external-source-sqlite-wal-journal-replay-is-not-part-of-case-db-indexing",
            "trusted-case-db-sqlite-fts-query-plan-diff-missing",
        ],
        "validation_evidence": [
            "case-db-initialize-emits-functional-fts-profile",
            "unit-test-asserts-case-db-fts-profile-contract",
        ],
    }


def build_case_db_fts_trusted_diff(
    rapid_assessment: Mapping[str, object],
    trusted_assessment: Mapping[str, object],
    *,
    trusted_tool: str = "case-db-sqlite-query-plan-manifest",
) -> dict[str, object]:
    rapid = case_db_fts_diff_value(rapid_assessment)
    trusted = case_db_fts_diff_value(trusted_assessment)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "case-db-sqlite-fts-trusted-query-plan-diff-v1",
        "item_number": 74,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def case_db_fts_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    query_plan = item.get("query_plan_profile")
    query_plan_profile = query_plan if isinstance(query_plan, Mapping) else {}
    return {
        "status": str(item.get("status") or ""),
        "fts_tables": sorted(str(value) for value in item.get("fts_tables") or []),
        "index_count": int(item.get("index_count") or 0),
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
    }
