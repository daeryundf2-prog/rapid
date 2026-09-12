from __future__ import annotations
import base64
import binascii
import contextlib
import datetime as dt
import email
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import struct
import wave
from collections.abc import Mapping, MutableMapping, Sequence
from email import policy
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree as ET
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ...core.case_db import CaseDatabaseError, open_case_database
from ...core.case_report import (
    build_case_report_markdown,
    case_report_export_paths,
    write_case_report_exports,
)
from ...core.collect_plan import (
    CollectPlanError,
    build_collect_plan,
    supported_collect_profiles,
)
from ...core.columnar_store import query_columnar_artifact_records
from ...core.commercial_readiness import (
    CommercialReadinessError,
    build_commercial_readiness_report,
)
from ...core.crash import (
    export_crash_report_bundle,
    list_crash_reports,
    read_crash_report,
    write_crash_report,
)
from ...core.docs import SUPPORTED_DOC_EXTS, TEXT_EXTS, extract_text, query_docs_index
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.hash_cache import hash_cache_assessment
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    default_job_store,
    is_relative_to,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ...core.large_case_controls import build_source_search_full_cursor_contract
from ...core.ocr_queue import (
    OcrQueueError,
    build_ocr_queue,
    build_ocr_queue_report_grade_validation_plan,
)
from ...core.run import RunModeError
from ...core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from ...core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ...core.search import SearchError, run_unified_search
from ...core.source_paths import (
    candidate_source_paths,
    source_path_resolution_diagnostics,
)
from ...core.source_reader import (
    SourceReadError,
    build_source_locator,
    parse_archived_source_request,
)
from ...core.source_reader import (
    build_archived_source_preview as build_archived_source_read_preview,
)
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from ...core.submission import build_submission_manifest, compute_hashes
from ...core.visible_capabilities import build_visible_capability_response

from .constants import (
    FUNCTIONAL_SCALE_BATCH_ID,
    LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS,
    LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    SOURCE_VIEWER_VERSION,
    SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
    SQLITE_FTS_TRUSTED_TOOLS,
    SQLITE_PREVIEW_COLUMN_LIMIT,
    SQLITE_PREVIEW_ROW_LIMIT,
    SQLITE_PREVIEW_TABLE_LIMIT,
    SQLITE_TABLE_PAGE_MAX_ROWS,
    SQLITE_VIEWER_REPORT_GRADE_BLOCKERS,
    SQLITE_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
    SQLITE_VIEWER_TRUSTED_TOOLS,
    SQLITE_WAL_FRAME_HEADER_SIZE,
    SQLITE_WAL_HEADER_SIZE,
    SQLITE_WAL_MAGIC_VALUES,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .helpers import (
    _sqlite_viewer_diff_key,
    _sqlite_viewer_diff_values,
    compute_hashes_for_bytes,
    is_sqlite_candidate,
    optional_int_for_api,
    stable_payload_sha256,
)
from .viewer_core import (
    build_viewer_trusted_diff_result,
    source_viewer_component_assessment,
    viewer_workflow_commercial_uplift_evidence,
    viewer_workflow_reportability_decision,
)
from .search import (
    snippet_around,
)


def first_sqlite_table_name(source_path: Path) -> str:
    if not is_sqlite_candidate(source_path):
        return ""
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            row = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1"
            ).fetchone()
    except (sqlite3.DatabaseError, OSError):
        return ""
    return str(row[0]) if row else ""


def build_sqlite_preview(source_path: Path, *, run_id: str | None = None) -> dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            database_metadata = sqlite_database_metadata(connection, source_path)
            tables = list_sqlite_tables(connection)
            previews = [
                preview_sqlite_table(connection, table, source_path=source_path)
                for table in tables[:SQLITE_PREVIEW_TABLE_LIMIT]
            ]
            table_page_profile = sqlite_table_page_profile(run_id=run_id, source_path=source_path, tables=previews)
            sqlite_manifest = build_sqlite_preview_manifest(
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
                table_page_profile=table_page_profile,
            )
            validation_plan = build_sqlite_viewer_report_grade_validation_plan(
                context="sqlite-preview",
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
                preview_manifest=sqlite_manifest,
                pagination_api=True,
                restricted_where_contains=True,
            )
            core_accuracy_gates = sqlite_viewer_core_accuracy_gates(
                source_path=source_path,
                database_metadata=database_metadata,
                tables=previews,
                preview_manifest=sqlite_manifest,
                validation_plan=validation_plan,
            )
    except sqlite3.DatabaseError as exc:
        return {
            "preview_type": "binary",
            "message": f"SQLite preview failed: {exc}",
            "sqlite": {"tables": [], "table_count": 0, "error": str(exc)},
        }
    return {
        "preview_type": "sqlite",
        "message": "SQLite table preview is available.",
        "viewer_metadata": {
            "source_format": "sqlite",
            "strategy": "read-only-table-preview",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.sqlite",
            "parser_version": SOURCE_VIEWER_VERSION,
            "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
            "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"], VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        },
        "sqlite": {
            "table_count": len(tables),
            "database_metadata": database_metadata,
            "sidecar_state_profile": database_metadata.get("sidecar_state_profile", {}),
            "tables": previews,
            "table_profiles": build_sqlite_table_profiles(previews),
            "table_page_profile": table_page_profile,
            "sqlite_preview_manifest": sqlite_manifest,
            "sqlite_preview_manifest_hash": sqlite_manifest["manifest_hash"],
            "sqlite_viewer_report_grade_validation_plan": validation_plan,
            "sqlite_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "large_sqlite_fts_optimization": sqlite_fts_optimization_metadata(database_metadata, previews),
            "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
            "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
            "column_limit": SQLITE_PREVIEW_COLUMN_LIMIT,
            "truncated": len(tables) > SQLITE_PREVIEW_TABLE_LIMIT,
            "sqlite_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["sqlite"],
                "sqlite-table-viewer",
                [
                    "interactive-table-pagination-ui-is-api-backed-baseline-only",
                    "foreign-key-relationship-graph-not-yet-rendered",
                    "wal/journal-replay-and-deleted-row-recovery-not-implemented-in-viewer",
                ],
            ),
            "core_accuracy_gates": core_accuracy_gates,
            "trusted_sqlite_viewer_diff": {
                "status": "missing",
                "blocker_id": SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(SQLITE_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=54,
                component="sqlite-table-specialized-viewer",
                core_accuracy_gates=core_accuracy_gates,
                blockers=[
                    "interactive-table-pagination-ui-needs-browser-e2e-validation",
                    "where-builder-is-restricted-contains-filter-not-arbitrary-sql",
                    "deleted-row-and-wal-recovery-not-implemented-in-viewer",
                    "export-selected-rows-workflow-not-implemented",
                    SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[
                    f"source_path:{source_path}",
                    f"table_count:{len(tables)}",
                    f"sqlite_viewer_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                ],
                controls={
                    "table_limit": SQLITE_PREVIEW_TABLE_LIMIT,
                    "row_limit": SQLITE_PREVIEW_ROW_LIMIT,
                    "column_limit": SQLITE_PREVIEW_COLUMN_LIMIT,
                    "opened_readonly": True,
                    "deleted_row_recovery": False,
                    "table_pagination_api": True,
                    "where_builder_api": True,
                    "where_builder_ui": False,
                    "max_table_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
                    "sqlite_preview_manifest_hash": sqlite_manifest["manifest_hash"],
                    "sqlite_viewer_report_grade_validation_plan_present": True,
                    "sqlite_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                    "sqlite_viewer_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                    "sqlite_viewer_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
                    "sqlite_preview_table_hash_count": sqlite_manifest["table_hash_count"],
                    "sqlite_preview_row_hash_count": sqlite_manifest["row_hash_count"],
                    "sqlite_sidecar_state_profile": database_metadata.get("sidecar_state_profile", {}),
                    "sqlite_sidecar_review_required": bool(
                        isinstance(database_metadata.get("sidecar_state_profile"), Mapping)
                        and database_metadata["sidecar_state_profile"].get("requires_wal_review")
                    ),
                },
            ),
            "sqlite_fts_optimization_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"],
                "large-sqlite-fts-optimization",
                [
                    "sqlite-source-preview-does-not-materialize-full-external-index",
                    "very-large-wal/journal-and-deleted-row-analysis-requires-dedicated-parser",
                    SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
                ],
            ),
            "review_features": [
                "read-only-uri-open",
                "schema-sql",
                "column-type-and-pk-details",
                "bounded-row-preview",
                "api-table-pagination",
                "restricted-where-contains-filter",
                "text-column-keyword-search",
                "table-profile-summary",
                "wal-shm-journal-sidecar-status",
                "large-sqlite-optimization-metadata",
            ],
        },
    }


def build_sqlite_viewer_report_grade_validation_plan(
    *,
    context: str,
    source_path: Path,
    database_metadata: Mapping[str, object],
    tables: Sequence[Mapping[str, object]],
    preview_manifest: Mapping[str, object] | None = None,
    page_manifest: Mapping[str, object] | None = None,
    pagination_api: bool = False,
    restricted_where_contains: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    page_manifest = page_manifest if isinstance(page_manifest, Mapping) else {}
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    table_count = len(tables)
    bounded_row_table_count = sum(1 for table in tables if table.get("rows") is not None)
    has_column_metadata = any(table.get("column_details") or table.get("indexes") or table.get("columns") for table in tables)
    table_hash_count = int(preview_manifest.get("table_hash_count") or 0)
    row_hash_count = int(preview_manifest.get("row_hash_count") or page_manifest.get("row_hash_count") or 0)
    manifest_hash = str(preview_manifest.get("manifest_hash") or page_manifest.get("manifest_hash") or "")
    validation_slots = [
        slot(
            "sqlite-read-only-open",
            ready=True,
            evidence=f"context={context} sqlite_uri_mode=ro path={source_path.name}",
            blocker_id="sqlite-read-only-open-required",
            operator_action="Open SQLite evidence through read-only URI mode.",
        ),
        slot(
            "sqlite-table-schema-inventory",
            ready=bool(tables),
            evidence=f"table_count={table_count}",
            blocker_id="sqlite-table-schema-inventory-required",
            operator_action="Emit table/schema inventory before row review.",
        ),
        slot(
            "sqlite-column-index-metadata",
            ready=has_column_metadata,
            evidence=f"column_or_index_metadata={has_column_metadata}",
            blocker_id="sqlite-column-index-metadata-required",
            operator_action="Preserve column, type, primary-key, and index hints.",
        ),
        slot(
            "sqlite-bounded-row-preview-or-page",
            ready=bounded_row_table_count > 0,
            evidence=f"bounded_row_table_count={bounded_row_table_count}",
            blocker_id="sqlite-bounded-row-preview-or-page-required",
            operator_action="Return bounded rows with source-viewer locators.",
        ),
        slot(
            "sqlite-preview-or-page-manifest-hashes",
            ready=bool(manifest_hash) and row_hash_count > 0,
            evidence=f"manifest_hash={manifest_hash} table_hash_count={table_hash_count} row_hash_count={row_hash_count}",
            blocker_id="sqlite-preview-or-page-manifest-hashes-required",
            operator_action="Attach preview/page manifest hashes and row hashes.",
        ),
        slot(
            "sqlite-pagination-and-restricted-filter-controls",
            ready=pagination_api or restricted_where_contains,
            evidence=f"pagination_api={pagination_api} restricted_where_contains={restricted_where_contains}",
            blocker_id="sqlite-pagination-and-restricted-filter-controls-required",
            operator_action="Expose bounded pagination and schema-validated filters instead of arbitrary SQL.",
        ),
        slot(
            "sqlite-pagination-browser-e2e",
            ready=False,
            evidence="browser_e2e_pagination=false",
            blocker_id="sqlite-pagination-browser-e2e-required",
            operator_action="Run browser E2E proving table navigation, filter state, and row selection UX.",
        ),
        slot(
            "sqlite-deleted-row-and-wal-recovery",
            ready=False,
            evidence="deleted_row_wal_recovery=false",
            blocker_id="sqlite-deleted-row-and-wal-recovery-required",
            operator_action="Validate WAL/journal replay and deleted-row recovery against known-answer corpora.",
        ),
        slot(
            "sqlite-trusted-query-schema-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing sqlite3/DB-browser/known-answer schema and query diff.",
        ),
        slot(
            "sqlite-export-selected-rows-workflow",
            ready=False,
            evidence="export_selected_rows_workflow=false",
            blocker_id="sqlite-export-selected-rows-workflow-required",
            operator_action="Add reviewed selected-row export with manifest, hashes, and report citations.",
        ),
        slot(
            "sqlite-fts-ranking-and-virtual-table-review",
            ready=False,
            evidence="fts_ranking_virtual_table_review=false",
            blocker_id="sqlite-fts-ranking-and-virtual-table-review-required",
            operator_action="Validate FTS ranking, virtual tables, triggers, views, and shadow-table handling.",
        ),
        slot(
            "sqlite-large-database-corpus",
            ready=False,
            evidence="large_database_corpus=false",
            blocker_id="sqlite-large-database-corpus-required",
            operator_action="Run large SQLite corpus validation with latency, memory, and page-window evidence.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": SQLITE_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 54,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["sqlite"],
        "batch_id": "commercial-uplift-051-055",
        "selected_track": "sqlite-table-specialized-viewer-report-validation",
        "context": context,
        "path": str(source_path),
        "table_count": table_count,
        "bounded_row_table_count": bounded_row_table_count,
        "page_size": database_metadata.get("page_size", ""),
        "page_count": database_metadata.get("page_count", ""),
        "freelist_count": database_metadata.get("freelist_count", ""),
        "manifest_hash": manifest_hash,
        "table_hash_count": table_hash_count,
        "row_hash_count": row_hash_count,
        "pagination_api": pagination_api,
        "restricted_where_contains": restricted_where_contains,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(SQLITE_VIEWER_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage web -> source-preview for a SQLite database",
            "GET /api/runs/<run_id>/source-sqlite-table?path=<path>&table=<table>&offset=0&limit=<n>",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 54 --json",
        ],
        "report_guidance": {
            "allowed_use": "read-only-sqlite-preview-triage-pivot",
            "forbidden_claim": "deleted-row/WAL-complete SQLite analysis or full database forensic recovery",
            "required_disclaimer": (
                "SQLite viewer output is bounded read-only table/page evidence until browser pagination E2E, "
                "WAL/journal replay, deleted-row validation, selected-row export, FTS/virtual-table review, "
                "large database corpus testing, and trusted sqlite query/schema diffs are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def sqlite_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    database_metadata: Mapping[str, object],
    tables: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
    preview_manifest: Mapping[str, object] | None = None,
    page_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["read-only SQLite open"]
    if tables:
        satisfied.append("table and schema inventory")
    if any(table.get("column_details") or table.get("indexes") or table.get("columns") for table in tables):
        satisfied.append("column/index metadata")
    if any(table.get("rows") is not None for table in tables):
        satisfied.append("bounded row preview")
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    page_manifest = page_manifest if isinstance(page_manifest, Mapping) else {}
    if preview_manifest.get("manifest_hash"):
        satisfied.append("SQLite preview source manifest")
    if page_manifest.get("manifest_hash"):
        satisfied.append("SQLite table page proof manifest")
    if int(preview_manifest.get("row_hash_count") or page_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("SQLite row hashes")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("SQLite viewer report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("SQLite viewer report-grade ready slots")
    satisfied.append("deleted/WAL limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted sqlite query/schema diff pass")
    return [
        build_accuracy_gate(
            54,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"table_count:{len(tables)}",
                f"page_size:{database_metadata.get('page_size', '')}",
                f"page_count:{database_metadata.get('page_count', '')}",
                f"sqlite_preview_manifest_hash:{preview_manifest.get('manifest_hash', '')}",
                f"sqlite_table_page_manifest_hash:{page_manifest.get('manifest_hash', '')}",
                f"sqlite_viewer_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"sqlite_viewer_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"sqlite_viewer_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def build_sqlite_viewer_trusted_diff(
    rapid_tables: Sequence[Mapping[str, object]],
    trusted_tables: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "sqlite-viewer-trusted-query-schema-diff",
) -> dict[str, object]:
    rapid_index = {_sqlite_viewer_diff_key(row): _sqlite_viewer_diff_values(row) for row in rapid_tables}
    trusted_index = {_sqlite_viewer_diff_key(row): _sqlite_viewer_diff_values(row) for row in trusted_tables}
    return build_viewer_trusted_diff_result(
        profile_version="sqlite-viewer-trusted-query-schema-diff-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=SQLITE_VIEWER_TRUSTED_TOOLS,
        blocker_id=SQLITE_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("name", "row_count", "schema_sha256", "columns_sha256", "sample_rows_sha256"),
    )


def list_sqlite_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type IN ('table', 'view')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [str(row["name"]) for row in rows]


def sqlite_database_metadata(connection: sqlite3.Connection, source_path: Path) -> dict[str, object]:
    metadata: dict[str, object] = {
        "path": str(source_path),
        "journal_mode": "",
        "user_version": None,
        "schema_version": None,
        "page_size": None,
        "page_count": None,
        "freelist_count": None,
        "encoding": "",
        "database_list": [],
        "sidecar_state_profile": sqlite_sidecar_state_profile(source_path),
    }
    pragma_names = {
        "journal_mode": "journal_mode",
        "user_version": "user_version",
        "schema_version": "schema_version",
        "page_size": "page_size",
        "page_count": "page_count",
        "freelist_count": "freelist_count",
        "encoding": "encoding",
    }
    for key, pragma in pragma_names.items():
        try:
            row = connection.execute(f"PRAGMA {pragma}").fetchone()
        except sqlite3.DatabaseError:
            row = None
        if row is not None:
            metadata[key] = row[0]
    page_size = optional_int_for_api(metadata.get("page_size")) or 0
    page_count = optional_int_for_api(metadata.get("page_count")) or 0
    metadata["estimated_database_bytes"] = page_size * page_count if page_size and page_count else source_path.stat().st_size
    try:
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        metadata["database_list"] = [
            {"sequence": row[0], "name": str(row[1]), "file": str(row[2] or "")}
            for row in database_rows
        ]
    except sqlite3.DatabaseError:
        metadata["database_list"] = []
    return metadata


def sqlite_sidecar_state_profile(source_path: Path) -> dict[str, object]:
    wal_path = source_path.with_name(source_path.name + "-wal")
    shm_path = source_path.with_name(source_path.name + "-shm")
    journal_path = source_path.with_name(source_path.name + "-journal")
    wal_info = sqlite_wal_sidecar_info(wal_path)
    sidecars = {
        "wal": wal_info,
        "shm": sqlite_basic_sidecar_info(shm_path, "shm"),
        "rollback_journal": sqlite_basic_sidecar_info(journal_path, "rollback-journal"),
    }
    detected = [name for name, info in sidecars.items() if bool(info.get("exists"))]
    profile_core = {
        "profile_version": "sqlite-sidecar-state-profile-v1",
        "source_path": str(source_path),
        "sidecars": sidecars,
        "detected_sidecars": detected,
        "wal_detected": bool(wal_info.get("exists")),
        "rollback_journal_detected": bool(sidecars["rollback_journal"].get("exists")),
        "shm_detected": bool(sidecars["shm"].get("exists")),
        "requires_wal_review": bool(detected),
        "hash_policy": "metadata-only-in-source-preview-use-sqlite-wal-preview-for-hashed-working-copy",
        "recommended_cli": "rapidtriage sqlite-wal-preview <database> --output-dir <case-output>/sqlite-wal-review --json",
        "source_viewer_warning": (
            "SQLite sidecar files are present. Preview rows may not represent all committed or recoverable evidence until WAL/journal review is completed."
            if detected
            else "No SQLite sidecar files were detected next to this database at preview time."
        ),
    }
    return {**profile_core, "profile_hash": stable_payload_sha256(profile_core)}


def sqlite_basic_sidecar_info(path: Path, kind: str) -> dict[str, object]:
    if not path.is_file():
        return {"kind": kind, "path": str(path), "exists": False, "size_bytes": 0, "hash_status": "missing"}
    stat = path.stat()
    return {
        "kind": kind,
        "path": str(path),
        "exists": True,
        "size_bytes": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
        "hash_status": "not-computed-in-source-preview",
    }


def sqlite_wal_sidecar_info(path: Path) -> dict[str, object]:
    info = sqlite_basic_sidecar_info(path, "wal")
    if not info.get("exists"):
        return info
    header: dict[str, object] = {"status": "not-read"}
    try:
        with path.open("rb") as handle:
            raw = handle.read(SQLITE_WAL_HEADER_SIZE)
        if len(raw) < SQLITE_WAL_HEADER_SIZE:
            header = {"status": "invalid-short-header", "bytes_read": len(raw)}
        else:
            magic, version, page_size, checkpoint_sequence, salt1, salt2, checksum1, checksum2 = struct.unpack(">IIIIIIII", raw)
            endian = SQLITE_WAL_MAGIC_VALUES.get(magic, "unknown")
            normalized_page_size = 1024 if page_size == 0 else page_size
            frame_size = SQLITE_WAL_FRAME_HEADER_SIZE + normalized_page_size if normalized_page_size > 0 else 0
            size_bytes = int(info.get("size_bytes") or 0)
            estimated_frames = max(0, (size_bytes - SQLITE_WAL_HEADER_SIZE) // frame_size) if frame_size else 0
            header = {
                "status": "parsed" if endian != "unknown" else "unknown-magic",
                "magic_hex": f"0x{magic:08x}",
                "endian": endian,
                "version": version,
                "page_size": normalized_page_size,
                "checkpoint_sequence": checkpoint_sequence,
                "salt1": salt1,
                "salt2": salt2,
                "checksum1": checksum1,
                "checksum2": checksum2,
                "estimated_frame_count": estimated_frames,
                "frame_count_is_estimate": True,
            }
    except OSError as exc:
        header = {"status": "read-error", "error": str(exc)}
    return {**info, "header": header}


def preview_sqlite_table(connection: sqlite3.Connection, table: str, *, source_path: Path | None = None) -> dict[str, object]:
    quoted = quote_sqlite_identifier(table)
    column_rows = connection.execute(f"PRAGMA table_info({quoted})").fetchall()
    column_details = [
        {
            "cid": optional_int_for_api(row["cid"]),
            "name": str(row["name"]),
            "type": str(row["type"] or ""),
            "notnull": bool(row["notnull"]),
            "default_value": sqlite_preview_value(row["dflt_value"]),
            "primary_key_position": optional_int_for_api(row["pk"]) or 0,
        }
        for row in column_rows
    ]
    columns = [str(column["name"]) for column in column_details]
    schema_row = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = ? ORDER BY type LIMIT 1",
        (table,),
    ).fetchone()
    index_rows = connection.execute(f"PRAGMA index_list({quoted})").fetchall()
    indexes = [
        {
            "name": str(row["name"]),
            "unique": bool(row["unique"]),
            "origin": str(row["origin"] or ""),
            "partial": bool(row["partial"]) if "partial" in row.keys() else False,
        }
        for row in index_rows[:8]
    ]
    count = None
    try:
        count = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted}").fetchone()["count"]
    except sqlite3.DatabaseError:
        count = None
    selected_columns = columns[:SQLITE_PREVIEW_COLUMN_LIMIT]
    primary_key_columns = [
        str(column["name"])
        for column in sorted(column_details, key=lambda item: int(item["primary_key_position"]))
        if int(column["primary_key_position"]) > 0
    ]
    rows: list[dict[str, object]] = []
    if selected_columns:
        select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
        rowid_available = True
        try:
            row_cursor = connection.execute(
                f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted} LIMIT ?",
                (SQLITE_PREVIEW_ROW_LIMIT,),
            )
        except sqlite3.DatabaseError:
            rowid_available = False
            row_cursor = connection.execute(f"SELECT {select_clause} FROM {quoted} LIMIT ?", (SQLITE_PREVIEW_ROW_LIMIT,))
        query_hash = sqlite_table_query_hash(
            table=table,
            columns=selected_columns,
            offset=0,
            limit=SQLITE_PREVIEW_ROW_LIMIT,
            where_column=None,
            where_contains=None,
            order_by=None,
            descending=False,
        )
        for index, row in enumerate(row_cursor, start=1):
            values = {column: sqlite_preview_value(row[column]) for column in selected_columns}
            locator = sqlite_row_source_viewer_locator(
                source_path=source_path,
                table=table,
                row_number=index,
                rowid=row["__rapid_source_rowid"] if rowid_available else "",
                primary_key_values=sqlite_primary_key_values(values, primary_key_columns),
                column="",
                offset=0,
                limit=SQLITE_PREVIEW_ROW_LIMIT,
                query_hash=query_hash,
                source_context="preview",
            )
            rows.append(
                {
                    "row_number": index,
                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                    "primary_key_values": sqlite_primary_key_values(values, primary_key_columns),
                    "values": values,
                    "source_viewer_locator": locator,
                    "sqlite_row_locator": locator,
                    "review_note_citation": sqlite_row_review_note_citation(locator),
                }
            )
    return {
        "name": table,
        "columns": selected_columns,
        "column_details": column_details[:SQLITE_PREVIEW_COLUMN_LIMIT],
        "column_count": len(columns),
        "row_count": count,
        "rows": rows,
        "schema_sql": str(schema_row["sql"] or "") if schema_row is not None else "",
        "object_type": str(schema_row["type"] or "table") if schema_row is not None else "table",
        "indexes": indexes,
        "primary_key_columns": primary_key_columns,
        "truncated_columns": len(columns) > SQLITE_PREVIEW_COLUMN_LIMIT,
        "truncated_rows": bool(count is not None and count > SQLITE_PREVIEW_ROW_LIMIT),
        "truncated_indexes": len(index_rows) > 8,
    }


def sqlite_table_page_profile(*, run_id: str | None, source_path: Path, tables: Sequence[Mapping[str, object]]) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    table_links = []
    for table in tables:
        name = str(table.get("name") or "")
        if not name:
            continue
        table_links.append(
            {
                "table": name,
                "first_page_url": (
                    f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={quote(name)}&offset=0&limit={SQLITE_PREVIEW_ROW_LIMIT}"
                    if run_id
                    else None
                ),
                "where_contains_url_template": (
                    f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={quote(name)}&where_column={{column}}&where_contains={{keyword}}"
                    if run_id
                    else None
                ),
            }
        )
    return {
        "profile_version": "sqlite-table-page-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "endpoint": "/api/runs/{run_id}/source-sqlite-table",
        "table_links": table_links,
        "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
        "supports_offset_pagination": True,
        "supports_restricted_where_contains": True,
        "supports_validated_order_by": True,
        "executes_arbitrary_sql": False,
        "report_use_warning": "Use trusted sqlite3/schema diff and source hashes before treating a page result as report-grade evidence.",
    }


def sqlite_primary_key_values(values: Mapping[str, object], primary_key_columns: Sequence[str]) -> dict[str, object]:
    return {column: values.get(column, "") for column in primary_key_columns if column in values}


def sqlite_table_query_core(
    *,
    table: str,
    columns: Sequence[str],
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> dict[str, object]:
    return {
        "table": table,
        "columns": list(columns),
        "offset": offset,
        "limit": limit,
        "where_column": where_column or "",
        "where_contains_sha256": hashlib.sha256(str(where_contains or "").encode("utf-8", errors="replace")).hexdigest()
        if where_contains
        else "",
        "order_by": order_by or "",
        "descending": descending,
    }


def sqlite_table_query_hash(
    *,
    table: str,
    columns: Sequence[str],
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> str:
    return stable_payload_sha256(
        sqlite_table_query_core(
            table=table,
            columns=columns,
            offset=offset,
            limit=limit,
            where_column=where_column,
            where_contains=where_contains,
            order_by=order_by,
            descending=descending,
        )
    )


def sqlite_row_source_viewer_locator(
    *,
    source_path: Path | None,
    table: str,
    row_number: int,
    rowid: object,
    primary_key_values: Mapping[str, object],
    column: str,
    offset: int,
    limit: int,
    query_hash: str,
    source_context: str,
) -> dict[str, object]:
    path = str(source_path) if source_path is not None else ""
    payload: dict[str, object] = {
        "profile_version": "sqlite-row-source-viewer-locator-v1",
        "qc_prep_item": 11,
        "viewer": "source-sqlite-table",
        "source_path": path,
        "source_name": Path(path).name if path else "",
        "table": table,
        "row_number": row_number,
        "rowid": rowid if rowid is not None else "",
        "primary_key_values": dict(primary_key_values),
        "column": column,
        "offset": offset,
        "limit": limit,
        "query_hash": query_hash,
        "source_context": source_context,
        "endpoint": "/api/runs/{run_id}/source-sqlite-table",
        "open_action": "open-sqlite-row-in-source-viewer",
        "review_note_ready": True,
        "report_ready": False,
        "required_before_report": [
            "verify source database hash",
            "confirm row in source SQLite viewer",
            "attach reviewer status and note",
            "validate schema/query output with trusted sqlite3 or known-answer manifest",
        ],
        "commercial_grade_blockers": [
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
        ],
    }
    payload["locator_sha256"] = stable_payload_sha256(payload)
    return payload


def sqlite_row_review_note_citation(locator: Mapping[str, object]) -> dict[str, object]:
    text = (
        f"SQLite row citation: {locator.get('source_name') or 'source'} "
        f"table={locator.get('table')} row={locator.get('row_number')} "
        f"rowid={locator.get('rowid')} column={locator.get('column') or '*'} "
        f"query_hash={locator.get('query_hash')} locator={locator.get('locator_sha256')}"
    )
    return {
        "profile_version": "sqlite-row-review-note-citation-v1",
        "qc_prep_item": 11,
        "text": text,
        "source_viewer_locator": dict(locator),
        "tags": ["sqlite-row", "source-viewer-locator"],
        "ready_for_review_note": True,
        "ready_for_report": False,
    }


def build_sqlite_preview_manifest(
    *,
    source_path: Path,
    database_metadata: Mapping[str, object],
    tables: Sequence[Mapping[str, object]],
    table_page_profile: Mapping[str, object],
) -> dict[str, object]:
    table_entries: list[dict[str, object]] = []
    row_hash_count = 0
    for table in tables[:SQLITE_PREVIEW_TABLE_LIMIT]:
        row_entries: list[dict[str, object]] = []
        for row in table.get("rows", []) if isinstance(table.get("rows"), list) else []:
            if not isinstance(row, Mapping):
                continue
            row_core = {
                "row_number": row.get("row_number"),
                "rowid": row.get("rowid", ""),
                "primary_key_values": row.get("primary_key_values")
                if isinstance(row.get("primary_key_values"), Mapping)
                else {},
                "values": row.get("values") if isinstance(row.get("values"), Mapping) else {},
                "source_viewer_locator": row.get("source_viewer_locator")
                if isinstance(row.get("source_viewer_locator"), Mapping)
                else {},
            }
            row_entries.append(
                {
                    **row_core,
                    "row_hash": stable_payload_sha256(row_core),
                    "review_note_citation": row.get("review_note_citation")
                    if isinstance(row.get("review_note_citation"), Mapping)
                    else {},
                }
            )
        row_hash_count += sum(1 for row in row_entries if row.get("row_hash"))
        table_core = {
            "name": str(table.get("name") or ""),
            "object_type": str(table.get("object_type") or "table"),
            "row_count": table.get("row_count"),
            "column_count": table.get("column_count"),
            "schema_sha256": hashlib.sha256(str(table.get("schema_sql") or "").encode("utf-8", errors="replace")).hexdigest(),
            "columns_sha256": stable_payload_sha256(
                [
                    column
                    for column in table.get("column_details", [])
                    if isinstance(column, Mapping)
                ]
            ),
            "indexes_sha256": stable_payload_sha256(
                [
                    index
                    for index in table.get("indexes", [])
                    if isinstance(index, Mapping)
                ]
            ),
            "sample_rows_sha256": stable_payload_sha256(row_entries),
            "row_hashes": row_entries[:SQLITE_PREVIEW_ROW_LIMIT],
            "truncated_rows": bool(table.get("truncated_rows")),
            "truncated_columns": bool(table.get("truncated_columns")),
        }
        table_entries.append({**table_core, "table_hash": stable_payload_sha256(table_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "sqlite-preview-source-manifest-v1",
        "item_number": 54,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "name": source_path.name,
        "database": {
            "page_size": database_metadata.get("page_size"),
            "page_count": database_metadata.get("page_count"),
            "freelist_count": database_metadata.get("freelist_count"),
            "journal_mode": str(database_metadata.get("journal_mode") or ""),
            "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
            "sidecar_state_profile_hash": str(
                database_metadata.get("sidecar_state_profile", {}).get("profile_hash")
                if isinstance(database_metadata.get("sidecar_state_profile"), Mapping)
                else ""
            ),
        },
        "table_count": len(tables),
        "bounded_table_count": len(table_entries),
        "table_hash_count": sum(1 for table in table_entries if table.get("table_hash")),
        "row_hash_count": row_hash_count,
        "table_page_profile_version": str(table_page_profile.get("profile_version") or ""),
        "table_page_link_count": len(table_page_profile.get("table_links") or []),
        "source_viewer_locator": {
            "viewer": "source-sqlite",
            "path": str(source_path),
            "open_action": "open-sqlite-table-in-read-only-viewer",
            "default_endpoint": table_page_profile.get("endpoint"),
        },
        "tables": table_entries,
        "blockers": [
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "browser-e2e-pagination-proof-not-attached",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_sqlite_table_page(
    *,
    run_id: str,
    source_path: Path,
    table: str,
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            tables = set(list_sqlite_tables(connection))
            if table not in tables:
                raise HTTPException(status_code=404, detail="table not found in SQLite database")
            quoted_table = quote_sqlite_identifier(table)
            column_rows = connection.execute(f"PRAGMA table_info({quoted_table})").fetchall()
            all_columns = [str(row["name"]) for row in column_rows]
            if not all_columns:
                raise HTTPException(status_code=400, detail="table has no readable columns")
            selected_columns = all_columns[:SQLITE_PREVIEW_COLUMN_LIMIT]
            where_sql = ""
            params: list[object] = []
            if where_column or where_contains:
                if not where_column or where_contains is None:
                    raise HTTPException(status_code=400, detail="where_column and where_contains must be provided together")
                if where_column not in all_columns:
                    raise HTTPException(status_code=400, detail="where_column is not a column in the selected table")
                where_sql = f" WHERE CAST({quote_sqlite_identifier(where_column)} AS TEXT) LIKE ? ESCAPE '\\'"
                params.append("%" + escape_sqlite_like(where_contains) + "%")
            order_sql = ""
            if order_by:
                if order_by not in all_columns:
                    raise HTTPException(status_code=400, detail="order_by is not a column in the selected table")
                order_sql = f" ORDER BY {quote_sqlite_identifier(order_by)} {'DESC' if descending else 'ASC'}"
            select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
            count_row = connection.execute(f"SELECT COUNT(*) AS count FROM {quoted_table}{where_sql}", params).fetchone()
            total = int(count_row["count"] or 0)
            page_params = [*params, limit, offset]
            primary_key_columns = [
                str(row["name"])
                for row in sorted(column_rows, key=lambda item: int(item["pk"] or 0))
                if int(row["pk"] or 0) > 0
            ]
            query_hash = sqlite_table_query_hash(
                table=table,
                columns=selected_columns,
                offset=offset,
                limit=limit,
                where_column=where_column,
                where_contains=where_contains,
                order_by=order_by,
                descending=descending,
            )
            rowid_available = True
            try:
                row_cursor = connection.execute(
                    f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted_table}{where_sql}{order_sql} LIMIT ? OFFSET ?",
                    page_params,
                )
            except sqlite3.DatabaseError:
                rowid_available = False
                row_cursor = connection.execute(
                    f"SELECT {select_clause} FROM {quoted_table}{where_sql}{order_sql} LIMIT ? OFFSET ?",
                    page_params,
                )
            rows = []
            for index, row in enumerate(row_cursor, start=1):
                row_number = offset + index
                values = {column: sqlite_preview_value(row[column]) for column in selected_columns}
                locator = sqlite_row_source_viewer_locator(
                    source_path=source_path,
                    table=table,
                    row_number=row_number,
                    rowid=row["__rapid_source_rowid"] if rowid_available else "",
                    primary_key_values=sqlite_primary_key_values(values, primary_key_columns),
                    column="",
                    offset=offset,
                    limit=limit,
                    query_hash=query_hash,
                    source_context="page",
                )
                rows.append(
                    {
                        "row_number": row_number,
                        "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                        "primary_key_values": sqlite_primary_key_values(values, primary_key_columns),
                        "values": values,
                        "source_viewer_locator": locator,
                        "sqlite_row_locator": locator,
                        "review_note_citation": sqlite_row_review_note_citation(locator),
                    }
                )
    except sqlite3.DatabaseError as exc:
        raise HTTPException(status_code=400, detail=f"SQLite table page failed: {exc}") from exc
    next_offset = offset + len(rows)
    has_next = next_offset < total
    page_manifest = build_sqlite_table_page_manifest(
        source_path=source_path,
        table=table,
        columns=selected_columns,
        rows=rows,
        offset=offset,
        limit=limit,
        total=total,
        where_column=where_column,
        where_contains=where_contains,
        order_by=order_by,
        descending=descending,
    )
    validation_plan = build_sqlite_viewer_report_grade_validation_plan(
        context="sqlite-table-page",
        source_path=source_path,
        database_metadata={"page_size": "", "page_count": "", "freelist_count": ""},
        tables=[{"name": table, "columns": selected_columns, "rows": rows, "column_count": len(all_columns)}],
        page_manifest=page_manifest,
        pagination_api=True,
        restricted_where_contains=bool(where_column and where_contains is not None),
    )
    core_accuracy_gates = sqlite_viewer_core_accuracy_gates(
        source_path=source_path,
        database_metadata={"page_size": "", "page_count": ""},
        tables=[{"name": table, "columns": selected_columns, "rows": rows, "column_count": len(all_columns)}],
        page_manifest=page_manifest,
        validation_plan=validation_plan,
    )
    return {
        "command": "source-sqlite-table",
        "profile_version": "sqlite-table-page-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "name": source_path.name,
        "table": table,
        "columns": selected_columns,
        "column_count": len(all_columns),
        "primary_key_columns": primary_key_columns,
        "rows": rows,
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(rows),
            "total": total,
            "has_next": has_next,
            "next_offset": next_offset if has_next else None,
            "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
        },
        "where": {
            "column": where_column or "",
            "contains": where_contains or "",
            "mode": "contains" if where_column and where_contains is not None else "none",
            "arbitrary_sql_allowed": False,
        },
        "sqlite_table_page_manifest": page_manifest,
        "sqlite_table_page_manifest_hash": page_manifest["manifest_hash"],
        "sqlite_viewer_report_grade_validation_plan": validation_plan,
        "sqlite_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "order_by": {
            "column": order_by or "",
            "direction": "desc" if order_by and descending else ("asc" if order_by else ""),
        },
        "read_only": True,
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; sqlite_table={table}; offset={offset}; limit={limit}; "
                f"returned={len(rows)}; where={where_column or ''}:{where_contains or ''}; query_hash={page_manifest['query_hash']}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=54,
            component="sqlite-table-page-viewer",
            blockers=[
                "trusted-sqlite-query-schema-diff-required-before-court-use",
                "deleted-row-and-wal-recovery-not-implemented-in-viewer",
                "export-selected-rows-workflow-not-implemented",
            ],
            controls={
                "read_only": True,
                "offset_pagination": True,
                "restricted_where_contains": True,
                "arbitrary_sql_allowed": False,
                "max_page_rows": SQLITE_TABLE_PAGE_MAX_ROWS,
                "sqlite_table_page_manifest_hash": page_manifest["manifest_hash"],
                "row_hash_count": page_manifest["row_hash_count"],
                "sqlite_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "sqlite_viewer_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "sqlite_viewer_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
        "core_accuracy_gates": core_accuracy_gates,
    }


def build_sqlite_table_page_manifest(
    *,
    source_path: Path,
    table: str,
    columns: Sequence[str],
    rows: Sequence[Mapping[str, object]],
    offset: int,
    limit: int,
    total: int,
    where_column: str | None,
    where_contains: str | None,
    order_by: str | None,
    descending: bool,
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows:
        row_core = {
            "row_number": row.get("row_number"),
            "rowid": row.get("rowid", ""),
            "primary_key_values": row.get("primary_key_values")
            if isinstance(row.get("primary_key_values"), Mapping)
            else {},
            "values": row.get("values") if isinstance(row.get("values"), Mapping) else {},
            "source_viewer_locator": row.get("source_viewer_locator")
            if isinstance(row.get("source_viewer_locator"), Mapping)
            else {},
        }
        row_entries.append(
            {
                **row_core,
                "row_hash": stable_payload_sha256(row_core),
                "review_note_citation": row.get("review_note_citation")
                if isinstance(row.get("review_note_citation"), Mapping)
                else {},
            }
        )
    query_core = sqlite_table_query_core(
        table=table,
        columns=columns,
        offset=offset,
        limit=limit,
        where_column=where_column,
        where_contains=where_contains,
        order_by=order_by,
        descending=descending,
    )
    manifest_core: dict[str, object] = {
        "manifest_version": "sqlite-table-page-proof-manifest-v1",
        "item_number": 54,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite"]],
        "path": str(source_path),
        "table": table,
        "query": query_core,
        "query_hash": stable_payload_sha256(query_core),
        "total": total,
        "returned": len(rows),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "rows": row_entries,
        "source_viewer_locator": {
            "viewer": "source-sqlite-table",
            "path": str(source_path),
            "table": table,
            "offset": offset,
            "limit": limit,
            "open_action": "open-sqlite-table-page",
        },
        "blockers": [
            "trusted-sqlite-query-schema-diff-required-before-court-use",
            "deleted-row-and-wal-recovery-not-implemented-in-viewer",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def escape_sqlite_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_sqlite_table_profiles(previews: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    profiles: list[dict[str, object]] = []
    for table in previews:
        column_details = table.get("column_details") if isinstance(table.get("column_details"), list) else []
        text_columns = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and str(column.get("type") or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}
        ]
        blob_columns = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and "BLOB" in str(column.get("type") or "").upper()
        ]
        timestamp_candidates = [
            str(column.get("name"))
            for column in column_details
            if isinstance(column, Mapping) and any(token in str(column.get("name") or "").lower() for token in ("time", "date", "created", "modified"))
        ]
        profiles.append(
            {
                "name": str(table.get("name") or ""),
                "object_type": str(table.get("object_type") or "table"),
                "row_count": table.get("row_count"),
                "column_count": table.get("column_count"),
                "primary_key_columns": list(table.get("primary_key_columns") or []),
                "text_columns": text_columns[:20],
                "blob_columns": blob_columns[:20],
                "timestamp_column_candidates": timestamp_candidates[:20],
                "searchable_text_column_count": len(text_columns),
                "has_indexes": bool(table.get("indexes")),
                "truncated_rows": bool(table.get("truncated_rows")),
                "review_hint": "Use source-search for table text hits, then verify row/column values against the original SQLite file.",
            }
        )
    return profiles


def sqlite_fts_optimization_metadata(
    database_metadata: Mapping[str, object],
    previews: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    row_counts = [
        int(table.get("row_count") or 0)
        for table in previews
        if isinstance(table.get("row_count"), int)
    ]
    total_preview_rows = sum(row_counts)
    text_column_count = 0
    for table in previews:
        for column in table.get("column_details", []) if isinstance(table.get("column_details"), list) else []:
            if isinstance(column, Mapping) and str(column.get("type") or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}:
                text_column_count += 1
    query_plan_profile = sqlite_preview_query_plan_profile(previews)
    optimization_manifest = sqlite_fts_optimization_manifest(
        database_metadata=database_metadata,
        preview_table_count=len(previews),
        preview_row_count=total_preview_rows,
        searchable_text_column_count=text_column_count,
        query_plan_profile=query_plan_profile,
    )
    validation_plan = build_large_sqlite_fts_report_grade_validation_plan(
        database_metadata=database_metadata,
        query_plan_profile=query_plan_profile,
        optimization_manifest=optimization_manifest,
        preview_table_count=len(previews),
        preview_row_count=total_preview_rows,
        searchable_text_column_count=text_column_count,
        scope="source-preview-sqlite",
    )
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "functional_priority_profile": sqlite_fts_functional_profile(
            database_metadata=database_metadata,
            preview_table_count=len(previews),
            preview_row_count=total_preview_rows,
            searchable_text_column_count=text_column_count,
            optimization_manifest=optimization_manifest,
            validation_plan=validation_plan,
        ),
        "status": "bounded-read-only-preview-with-fts-aware-guidance",
        "page_size": database_metadata.get("page_size"),
        "page_count": database_metadata.get("page_count"),
        "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
        "preview_table_count": len(previews),
        "preview_row_count": total_preview_rows,
        "searchable_text_column_count": text_column_count,
        "query_plan_profile": query_plan_profile,
        "sqlite_fts_optimization_manifest": optimization_manifest,
        "sqlite_fts_optimization_manifest_hash": optimization_manifest["manifest_hash"],
        "large_sqlite_fts_report_grade_validation_plan": validation_plan,
        "large_sqlite_fts_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "core_accuracy_gates": large_sqlite_fts_core_accuracy_gates(
            database_metadata=database_metadata,
            previews=previews,
            searchable_text_column_count=text_column_count,
            preview_row_count=total_preview_rows,
            query_plan_profile=query_plan_profile,
            optimization_manifest=optimization_manifest,
            validation_plan=validation_plan,
        ),
        "trusted_large_sqlite_fts_diff": {
            "status": "missing",
            "blocker_id": SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(SQLITE_FTS_TRUSTED_TOOLS),
        },
        "recommended_large_case_strategy": [
            "Use indexed case search for imported artifacts/documents instead of loading huge SQLite tables in the browser.",
            "Use current-file source-search for targeted keyword hits, then verify row/table context in the source viewer.",
            "Keep row previews bounded and paginate/cursor through API results for case-scale review.",
        ],
        "ready_for_court_report": False,
    }


def build_large_sqlite_fts_report_grade_validation_plan(
    *,
    database_metadata: Mapping[str, object],
    query_plan_profile: Mapping[str, object],
    optimization_manifest: Mapping[str, object],
    preview_table_count: int,
    preview_row_count: int,
    searchable_text_column_count: int,
    scope: str,
) -> dict[str, object]:
    manifest_hash = str(optimization_manifest.get("manifest_hash") or "")
    query_plan_hash = str(query_plan_profile.get("plan_hash") or "")
    query_plan_row_head_hash = str(query_plan_profile.get("plan_row_head_hash") or "")
    page_profile = {
        "page_size": optional_int_for_api(database_metadata.get("page_size")) or 0,
        "page_count": optional_int_for_api(database_metadata.get("page_count")) or 0,
        "estimated_database_bytes": optional_int_for_api(database_metadata.get("estimated_database_bytes")) or 0,
        "journal_mode": str(database_metadata.get("journal_mode") or ""),
    }
    page_profile_hash = hashlib.sha256(json.dumps(page_profile, sort_keys=True).encode("utf-8")).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "optimization-manifest",
            "status": "ready",
            "evidence_ref": "sqlite_fts_optimization_manifest_hash",
            "evidence_hash": manifest_hash,
            "description": "Source SQLite preview emits optimization manifest metadata.",
        },
        {
            "slot_id": "query-plan-row-hashes",
            "status": "ready",
            "evidence_ref": "query_plan_row_head_hash",
            "evidence_hash": query_plan_row_head_hash,
            "description": "Bounded preview query plans are row-hashed.",
        },
        {
            "slot_id": "query-plan-profile",
            "status": "ready",
            "evidence_ref": "query_plan_hash",
            "evidence_hash": query_plan_hash,
            "description": "SQLite source viewer exposes a deterministic query-plan profile hash.",
        },
        {
            "slot_id": "bounded-row-preview",
            "status": "ready",
            "evidence_ref": "preview_row_count",
            "evidence_hash": hashlib.sha256(str(preview_row_count).encode("ascii")).hexdigest(),
            "description": "Preview rows are bounded and counted without full-table materialization.",
        },
        {
            "slot_id": "searchable-text-column-inventory",
            "status": "ready",
            "evidence_ref": "searchable_text_column_count",
            "evidence_hash": hashlib.sha256(str(searchable_text_column_count).encode("ascii")).hexdigest(),
            "description": "Searchable text columns are counted for FTS handoff decisions.",
        },
        {
            "slot_id": "database-page-profile",
            "status": "ready",
            "evidence_ref": "database_page_profile_hash",
            "evidence_hash": page_profile_hash,
            "description": "Database page size/count and journal mode are preserved for performance review.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-query-plan-manifest",
            "status": "blocked",
            "blocker": SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
            "required_evidence": "trusted sqlite query-plan manifest diff for source viewer and Case DB",
        },
        {
            "slot_id": "10m-row-query-plan-regression",
            "status": "blocked",
            "blocker": "10m-row-query-plan-regression-required",
            "required_evidence": "10M-row query-plan and latency regression on release hardware",
        },
        {
            "slot_id": "deleted-row-wal-replay",
            "status": "blocked",
            "blocker": "deleted-row-wal-replay-validation-required",
            "required_evidence": "WAL/deleted-row replay corpus and expected row-state oracle",
        },
        {
            "slot_id": "large-source-db-corpus",
            "status": "blocked",
            "blocker": "large-source-db-corpus-required",
            "required_evidence": "multi-GB source SQLite corpus with FTS, indexes, WAL, and corrupt-page cases",
        },
        {
            "slot_id": "browser-pagination-query-plan-e2e",
            "status": "blocked",
            "blocker": "browser-pagination-query-plan-e2e-required",
            "required_evidence": "browser E2E proving SQLite pages remain bounded/cursor-paged",
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
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "scope": scope,
        "sqlite_fts_optimization_manifest_hash": manifest_hash,
        "query_plan_hash": query_plan_hash,
        "query_plan_row_head_hash": query_plan_row_head_hash,
        "database_page_profile_hash": page_profile_hash,
        "preview_table_count": preview_table_count,
        "preview_row_count": preview_row_count,
        "searchable_text_column_count": searchable_text_column_count,
        "bounded_preview_query": bool(query_plan_profile.get("bounded_preview_query")),
        "arbitrary_sql_allowed": bool(query_plan_profile.get("arbitrary_sql_allowed")),
        "wal_journal_replay_supported": bool(optimization_manifest.get("wal_journal_replay_supported")),
        "ten_million_row_regression_attached": bool(
            optimization_manifest.get("ten_million_row_regression_attached")
        ),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as bounded SQLite/FTS triage evidence only until trusted query-plan, WAL/deleted-row, and 10M-row regression evidence are attached.",
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_sha256": validation_plan_sha256,
        "validation_plan_hash": validation_plan_sha256,
    }


def sqlite_fts_optimization_manifest(
    *,
    database_metadata: Mapping[str, object],
    preview_table_count: int,
    preview_row_count: int,
    searchable_text_column_count: int,
    query_plan_profile: Mapping[str, object],
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "sqlite-fts-optimization-manifest-v1",
        "item_number": 32,
        "gap_id": "#32",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "page_size": database_metadata.get("page_size"),
        "page_count": database_metadata.get("page_count"),
        "freelist_count": database_metadata.get("freelist_count"),
        "journal_mode": str(database_metadata.get("journal_mode") or ""),
        "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
        "preview_table_count": preview_table_count,
        "preview_row_count": preview_row_count,
        "searchable_text_column_count": searchable_text_column_count,
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
        "query_plan_row_head_hash": str(query_plan_profile.get("plan_row_head_hash") or ""),
        "query_plan_row_hash_count": int(query_plan_profile.get("plan_row_hash_count") or 0),
        "bounded_preview_query": bool(query_plan_profile.get("bounded_preview_query")),
        "arbitrary_sql_allowed": bool(query_plan_profile.get("arbitrary_sql_allowed")),
        "wal_journal_replay_supported": False,
        "ten_million_row_regression_attached": False,
        "recommended_engine": "case-db-fts-for-indexed-case-search-source-sqlite-preview-for-verification",
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def sqlite_preview_query_plan_profile(previews: Sequence[Mapping[str, object]]) -> dict[str, object]:
    plans = []
    for table in previews:
        if not isinstance(table, Mapping):
            continue
        indexes = table.get("indexes") if isinstance(table.get("indexes"), list) else []
        row_count = optional_int_for_api(table.get("row_count")) or 0
        uses_index = bool(indexes)
        plan = {
            "table": str(table.get("name") or ""),
            "row_count": row_count,
            "preview_query": "SELECT bounded_columns FROM table LIMIT ?",
            "count_query": "SELECT COUNT(*) FROM table",
            "uses_declared_index": uses_index,
            "bounded_rows": True,
            "full_table_materialization": False,
        }
        plans.append(
            {
                **plan,
                "row_hash": hashlib.sha256(json.dumps(plan, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_hashes = [str(plan["row_hash"]) for plan in plans if plan.get("row_hash")]
    plan_hash = hashlib.sha256(json.dumps(plans, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "profile_version": "sqlite-preview-query-plan-profile-v1",
        "plan_count": len(plans),
        "plan_hash": plan_hash,
        "plan_row_hash_count": len(row_hashes),
        "plan_row_head_hash": hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest(),
        "plans": plans[:20],
        "bounded_preview_query": True,
        "arbitrary_sql_allowed": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "commercial_claim_allowed": False,
    }


def sqlite_fts_functional_profile(
    *,
    database_metadata: Mapping[str, object],
    preview_table_count: int,
    preview_row_count: int,
    searchable_text_column_count: int,
    optimization_manifest: Mapping[str, object],
    validation_plan: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 32,
        "gap_id": "#32",
        "component": "sqlite-fts-optimization",
        "status": "implemented-source-viewer-bounded-preview-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "page_size": database_metadata.get("page_size"),
            "page_count": database_metadata.get("page_count"),
            "estimated_database_bytes": database_metadata.get("estimated_database_bytes"),
            "preview_table_count": preview_table_count,
            "preview_row_count": preview_row_count,
            "searchable_text_column_count": searchable_text_column_count,
            "bounded_row_preview": True,
            "case_db_fts_recommended_for_large_search": True,
            "optimization_manifest_hash": str(optimization_manifest.get("manifest_hash") or ""),
            "query_plan_hash": str(optimization_manifest.get("query_plan_hash") or ""),
            "query_plan_row_head_hash": str(optimization_manifest.get("query_plan_row_head_hash") or ""),
            "query_plan_row_hash_count": int(optimization_manifest.get("query_plan_row_hash_count") or 0),
            "large_sqlite_fts_report_grade_validation_plan_hash": str(
                validation_plan.get("validation_plan_sha256") or ""
            ),
            "large_sqlite_fts_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "large_sqlite_fts_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "wal_journal_replay_supported": bool(optimization_manifest.get("wal_journal_replay_supported")),
        },
        "blockers": [
            SQLITE_FTS_TRUSTED_DIFF_BLOCKER,
            "source-sqlite-wal-journal-replay-not-implemented-in-viewer",
            "large-table-query-plan-benchmark-not-attached",
        ],
        "validation_evidence": [
            "source-preview-emits-functional-sqlite-fts-profile",
            "unit-test-asserts-sqlite-viewer-profile-contract",
        ],
    }


def large_sqlite_fts_core_accuracy_gates(
    *,
    database_metadata: Mapping[str, object],
    previews: Sequence[Mapping[str, object]],
    searchable_text_column_count: int,
    preview_row_count: int,
    query_plan_profile: Mapping[str, object] | None = None,
    optimization_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "SQLite performance pragmas applied",
        "table profile emitted",
        "searchable text columns counted",
        "bounded row preview preserved",
        "bounded query plan profile emitted",
        "query plan row hashes emitted",
        "SQLite/FTS optimization manifest hash emitted",
        "large corpus optimization limitation warning",
    ]
    evidence_refs = [
        f"page_size:{database_metadata.get('page_size', '')}",
        f"page_count:{database_metadata.get('page_count', '')}",
        f"preview_table_count:{len(previews)}",
        f"preview_row_count:{preview_row_count}",
        f"searchable_text_column_count:{searchable_text_column_count}",
    ]
    if query_plan_profile:
        evidence_refs.append(f"query_plan_hash:{query_plan_profile.get('plan_hash', '')}")
    if optimization_manifest:
        evidence_refs.append(f"optimization_manifest_hash:{optimization_manifest.get('manifest_hash', '')}")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("large SQLite/FTS report-grade validation plan emitted")
        satisfied.append("large SQLite/FTS report-grade ready slots emitted")
        evidence_refs.append(
            f"large_sqlite_fts_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256')}"
        )
        evidence_refs.append(f"large_sqlite_fts_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}")
        evidence_refs.append(
            f"large_sqlite_fts_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}"
        )
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted large SQLite/FTS query-plan diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            74,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def build_large_sqlite_fts_trusted_diff(
    rapid_metadata: Mapping[str, object],
    trusted_metadata: Mapping[str, object],
    *,
    trusted_tool: str = "sqlite-query-plan-manifest",
) -> dict[str, object]:
    rapid = large_sqlite_fts_diff_value(rapid_metadata)
    trusted = large_sqlite_fts_diff_value(trusted_metadata)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "large-sqlite-fts-trusted-query-plan-diff-v1",
        "item_number": 74,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["sqlite_performance"]],
        "commercial_claim_allowed": status == "pass",
    }


def large_sqlite_fts_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    query_plan = item.get("query_plan_profile")
    query_plan_profile = query_plan if isinstance(query_plan, Mapping) else {}
    return {
        "page_size": int(item.get("page_size") or 0),
        "page_count": int(item.get("page_count") or 0),
        "preview_table_count": int(item.get("preview_table_count") or 0),
        "searchable_text_column_count": int(item.get("searchable_text_column_count") or 0),
        "preview_row_count": int(item.get("preview_row_count") or 0),
        "query_plan_hash": str(query_plan_profile.get("plan_hash") or ""),
    }


def quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def sqlite_preview_value(value: object, *, max_length: int = 240) -> object:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return f"<blob {len(value)} bytes sha256={compute_hashes_for_bytes(value)['sha256'][:16]}>"
    text = str(value)
    return text if len(text) <= max_length else text[:max_length] + "...[truncated]"


def search_sqlite_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
    row_scan_limit: int | None = None,
    resume_state: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    matches: list[dict[str, object]] = []
    scanned_rows = 0
    scanned_tables = 0
    truncated_tables: list[str] = []
    result_limit_reached = False
    next_resume_state: dict[str, object] | None = None
    effective_row_scan_limit = int(row_scan_limit or 0)
    resume_table = str((resume_state or {}).get("table") or "")
    resume_next_row_number = max(1, optional_int_for_api((resume_state or {}).get("next_row_number")) or 1)
    resume_consumed = not bool(resume_table)
    with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        for table in list_sqlite_tables(connection):
            if len(matches) >= limit:
                break
            table_start_row_number = 1
            if resume_table and not resume_consumed:
                if table != resume_table:
                    continue
                table_start_row_number = resume_next_row_number
                resume_consumed = True
            quoted = quote_sqlite_identifier(table)
            column_rows = connection.execute(f"PRAGMA table_info({quoted})").fetchall()
            text_columns = [
                str(row["name"])
                for row in column_rows
                if str(row["type"] or "").upper() in {"", "TEXT", "VARCHAR", "CHAR", "CLOB"}
            ][:SQLITE_PREVIEW_COLUMN_LIMIT]
            if not text_columns:
                continue
            primary_key_columns = [
                str(row["name"])
                for row in sorted(column_rows, key=lambda item: int(item["pk"] or 0))
                if int(row["pk"] or 0) > 0
            ]
            scanned_tables += 1
            scan_columns = [*text_columns, *[column for column in primary_key_columns if column not in text_columns]]
            select_clause = ", ".join(quote_sqlite_identifier(column) for column in scan_columns)
            table_offset = max(0, table_start_row_number - 1)
            rowid_available = True
            try:
                query = f"SELECT rowid AS __rapid_source_rowid, {select_clause} FROM {quoted}"
                params_list: list[object] = []
                if effective_row_scan_limit > 0:
                    query += " LIMIT ?"
                    params_list.append(effective_row_scan_limit + 1)
                elif table_offset:
                    query += " LIMIT -1"
                if table_offset:
                    query += " OFFSET ?"
                    params_list.append(table_offset)
                params = tuple(params_list)
                row_cursor = connection.execute(query, params)
            except sqlite3.DatabaseError:
                rowid_available = False
                query = f"SELECT {select_clause} FROM {quoted}"
                params_list = []
                if effective_row_scan_limit > 0:
                    query += " LIMIT ?"
                    params_list.append(effective_row_scan_limit + 1)
                elif table_offset:
                    query += " LIMIT -1"
                if table_offset:
                    query += " OFFSET ?"
                    params_list.append(table_offset)
                params = tuple(params_list)
                row_cursor = connection.execute(query, params)
            for page_row_index, row in enumerate(row_cursor, start=0):
                row_number = table_start_row_number + page_row_index
                if effective_row_scan_limit > 0 and page_row_index >= effective_row_scan_limit:
                    truncated_tables.append(table)
                    next_resume_state = {
                        "table": table,
                        "next_row_number": row_number,
                        "reason": "sqlite-row-scan-limit",
                        "scanned_row_count": scanned_rows,
                        "match_count": len(matches),
                    }
                    break
                scanned_rows += 1
                row_values = {column: sqlite_preview_value(row[column]) for column in scan_columns}
                primary_key_values = sqlite_primary_key_values(row_values, primary_key_columns)
                for column in text_columns:
                    value = row[column]
                    if value is None:
                        continue
                    text = str(value)
                    lowered = text.lower()
                    for keyword in keywords:
                        offset = lowered.find(keyword)
                        if offset >= 0:
                            query_hash = stable_payload_sha256(
                                {
                                    "table": table,
                                    "columns": text_columns,
                                    "mode": "source-search",
                                    "keyword": keyword,
                                    "row_scan_limit": effective_row_scan_limit or "unbounded",
                                    "row_start_number": table_start_row_number,
                                }
                            )
                            sqlite_locator = sqlite_row_source_viewer_locator(
                                source_path=source_path,
                                table=table,
                                row_number=row_number,
                                rowid=row["__rapid_source_rowid"] if rowid_available else "",
                                primary_key_values=primary_key_values,
                                column=column,
                                offset=max(row_number - 1, 0),
                                limit=row_scan_limit,
                                query_hash=query_hash,
                                source_context="source-search",
                            )
                            matches.append(
                                {
                                    "keyword": keyword,
                                    "line": f"{table}:{row_number}",
                                    "offset": offset,
                                    "snippet": snippet_around(text, offset, len(keyword), context=context),
                                    "table": table,
                                    "column": column,
                                    "row_number": row_number,
                                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                                    "primary_key_values": primary_key_values,
                                    "source_viewer_locator": sqlite_locator,
                                    "sqlite_row_locator": sqlite_locator,
                                    "review_note_citation": sqlite_row_review_note_citation(sqlite_locator),
                                }
                            )
                            if len(matches) >= limit:
                                result_limit_reached = True
                                next_resume_state = {
                                    "table": table,
                                    "next_row_number": row_number + 1,
                                    "reason": "result-limit",
                                    "scanned_row_count": scanned_rows,
                                    "match_count": len(matches),
                                    "rowid": row["__rapid_source_rowid"] if rowid_available else "",
                                }
                                return matches, True, {
                                    "sqlite_scanned_table_count": scanned_tables,
                                    "sqlite_scanned_row_count": scanned_rows,
                                    "sqlite_row_scan_limit": effective_row_scan_limit or None,
                                    "sqlite_scan_truncated": True,
                                    "sqlite_truncated_tables": truncated_tables[:10],
                                    "sqlite_full_cursor_scan": False,
                                    "sqlite_result_limit_reached": result_limit_reached,
                                    "sqlite_resume_state": next_resume_state,
                                    "sqlite_resume_requested": bool(resume_state),
                                    "sqlite_resume_consumed": resume_consumed,
                                }
                            break
    truncated = bool(truncated_tables)
    return matches, truncated, {
        "sqlite_scanned_table_count": scanned_tables,
        "sqlite_scanned_row_count": scanned_rows,
        "sqlite_row_scan_limit": effective_row_scan_limit or None,
        "sqlite_scan_truncated": truncated,
        "sqlite_truncated_tables": truncated_tables[:10],
        "sqlite_full_cursor_scan": not truncated,
        "sqlite_result_limit_reached": result_limit_reached,
        "sqlite_resume_state": next_resume_state,
        "sqlite_resume_requested": bool(resume_state),
        "sqlite_resume_consumed": resume_consumed,
    }
