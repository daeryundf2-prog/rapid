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
    BROWSER_E2E_PERFORMANCE_CONTRACT_VERSION,
    DEFAULT_INTERNAL_VALIDATION_PACKAGE,
    DOCUMENT_PREVIEW_MAX_BYTES,
    EMAIL_PREVIEW_MAX_BYTES,
    FUNCTIONAL_SCALE_BATCH_ID,
    FUNCTIONAL_UI_BATCH_ID,
    HEX_PREVIEW_MAX_BYTES,
    PAGINATION_TRUSTED_DIFF_BLOCKER_78,
    PAGINATION_TRUSTED_TOOLS,
    PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS,
    PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
    PREVIEW_SANDBOX_TRUSTED_TOOLS,
    RUN_VIEWER_WORKFLOW_FAMILY_PRIORITY,
    RUN_VIEWER_WORKFLOW_REQUIRED_ROUTES,
    RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT,
    SOURCE_VIEWER_VERSION,
    STAGE10_CAPABILITY_SPECS,
    STAGE10_VIEWER_ITEM_BY_FAMILY,
    STRUCTURED_PREVIEW_MAX_BYTES,
    UI_VIRTUALIZATION_REPORT_GRADE_BLOCKERS,
    UI_VIRTUALIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
    UI_VIRTUALIZATION_TRUSTED_TOOLS,
    VIEWER_WORKFLOW_GAP_IDS,
    VIRTUAL_TABLE_ROW_LIMIT,
    WORKBENCH_SMOKE_CONTRACT_VERSION,
    WORKBENCH_SMOKE_SELECTORS,
)
from .helpers import (
    dt_from_epoch,
    extract_external_command_history,
    extract_tool_preflight,
    is_sqlite_candidate,
    preview_sandbox_core_accuracy_gates,
    stable_payload_sha256,
)


def collect_bounded_viewer_candidate_path_strings(
    allowed_roots: Sequence[Path],
    *,
    existing_raw_paths: Sequence[str],
) -> tuple[list[str], dict[str, object]]:
    seen = {
        str(candidate)
        for raw_path in existing_raw_paths
        for candidate in candidate_source_paths(raw_path, allowed_roots)
    }
    collected: list[str] = []
    scanned = 0
    for root in allowed_roots:
        if len(collected) >= RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT:
            break
        if not root.is_dir():
            continue
        for current_root, dir_names, file_names in os.walk(root):
            dir_names[:] = sorted(name for name in dir_names if not name.startswith("."))[:50]
            for file_name in sorted(file_names):
                if len(collected) >= RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT:
                    break
                path = (Path(current_root) / file_name).expanduser().resolve()
                scanned += 1
                if str(path) in seen or not path.is_file():
                    continue
                if source_viewer_family_for_path(path) in RUN_VIEWER_WORKFLOW_FAMILY_PRIORITY:
                    collected.append(str(path))
                    seen.add(str(path))
            if len(collected) >= RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT:
                break
    diagnostics = {
        "profile_version": "viewer-workflow-bounded-root-supplement-v1",
        "enabled": True,
        "scan_limit": RUN_VIEWER_WORKFLOW_SUPPLEMENTAL_SCAN_LIMIT,
        "scanned_file_count": scanned,
        "collected_path_count": len(collected),
        "purpose": "Find viewer families not present in the primary files/docs outputs without full evidence traversal.",
    }
    diagnostics["scan_hash"] = stable_payload_sha256(diagnostics)
    return collected, diagnostics


def run_viewer_candidate_sort_key(source_path: Path) -> tuple[int, int, str]:
    family = source_viewer_family_for_path(source_path)
    try:
        size = source_path.stat().st_size
    except OSError:
        size = 0
    return (
        int(RUN_VIEWER_WORKFLOW_FAMILY_PRIORITY.get(family, 99)),
        min(size, 10_000_000),
        source_path.name.lower(),
    )


def source_viewer_family_for_path(source_path: Path) -> str:
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    return source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)


def build_run_viewer_route_coverage(source_rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    coverage = {
        route_id: {
            "route_id": route_id,
            "implemented": True,
            "candidate_count": 0,
            "sample_ready_count": 0,
            "source_paths": [],
            "sample_urls": [],
        }
        for route_id in RUN_VIEWER_WORKFLOW_REQUIRED_ROUTES
    }
    for row in source_rows:
        routes = row.get("routes") if isinstance(row.get("routes"), Sequence) else []
        for route in routes:
            if not isinstance(route, Mapping):
                continue
            route_id = str(route.get("route_id") or "")
            if route_id not in coverage:
                continue
            entry = coverage[route_id]
            entry["candidate_count"] = int(entry["candidate_count"]) + 1
            if route.get("sample_ready"):
                entry["sample_ready_count"] = int(entry["sample_ready_count"]) + 1
            if len(entry["source_paths"]) < 5:
                entry["source_paths"].append(str(row.get("source_path") or ""))
            if len(entry["sample_urls"]) < 5:
                entry["sample_urls"].append(str(route.get("url") or ""))
    for entry in coverage.values():
        entry["sample_ready"] = int(entry["sample_ready_count"]) > 0
        entry["coverage_hash"] = stable_payload_sha256(entry)
    return coverage


def build_run_viewer_workflow_accuracy_gates(
    item_coverage: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    gates = []
    for row in item_coverage:
        item_number = int(row["item_number"])
        satisfied = [
            "viewer route contract emitted",
            "source locator validation emitted",
            "bounded large-data controls emitted",
        ]
        if row.get("validated_in_this_run"):
            satisfied.append("sample source route available in this run")
        gates.append(
            build_accuracy_gate(
                item_number,
                satisfied_checks=satisfied,
                evidence_refs=[
                    "viewer-workflow-validation.route_coverage",
                    "viewer-workflow-validation.source_viewer_rows",
                    "viewer-workflow-validation.item_coverage",
                ],
            )
        )
    return gates


def build_cursor_api_coverage_manifest(
    *,
    collection_name: str,
    total: int,
    returned: int,
    has_more: bool,
    pagination_manifest: Mapping[str, object],
) -> dict[str, object]:
    covered_families = [
        "files",
        "docs",
        "timeline",
        "indicators",
        "artifact-groups",
    ]
    required_families = [
        *covered_families,
        "search-results",
        "case-db-review-candidates",
        "report-candidates",
    ]
    missing_families = [family for family in required_families if family not in covered_families]
    manifest_core = {
        "profile": "cursor-api-coverage-manifest-v1",
        "item_number": 31,
        "gap_id": "#31",
        "collection": collection_name,
        "total": int(total),
        "returned": int(returned),
        "has_more": bool(has_more),
        "pagination_manifest_hash": str(pagination_manifest.get("manifest_hash") or ""),
        "page_window_id": str(pagination_manifest.get("page_window_id") or ""),
        "covered_endpoint_families": covered_families,
        "required_endpoint_families": required_families,
        "missing_endpoint_families": missing_families,
        "endpoint_family_count": len(covered_families),
        "bounded_limit": True,
        "cursor_tokens": True,
        "offset_compatible": True,
        "snapshot_isolation": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def cursor_api_functional_profile(
    collection_name: str,
    *,
    total: int,
    returned: int,
    has_more: bool,
    coverage_manifest: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 31,
        "gap_id": "#31",
        "component": "cursor-apis-everywhere",
        "status": "implemented-for-run-output-endpoints-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "collection": collection_name,
            "total": total,
            "returned": returned,
            "has_more": has_more,
            "cursor_tokens": True,
            "offset_compatible": True,
            "bounded_limit": True,
            "snapshot_isolation": False,
            "coverage_manifest_hash": str(coverage_manifest.get("manifest_hash") or ""),
            "pagination_manifest_hash": str(coverage_manifest.get("pagination_manifest_hash") or ""),
            "covered_endpoint_family_count": len(coverage_manifest.get("covered_endpoint_families", []))
            if isinstance(coverage_manifest.get("covered_endpoint_families"), list)
            else 0,
            "missing_endpoint_families": list(coverage_manifest.get("missing_endpoint_families", []))
            if isinstance(coverage_manifest.get("missing_endpoint_families"), list)
            else [],
        },
        "covered_endpoint_families": [
            "files",
            "docs",
            "timeline",
            "indicators",
            "artifact-groups",
        ],
        "blockers": [
            "case-db-review-and-report-candidate-pagination-still-needs-endpoint-level-proof",
            "cursor-is-offset-token-not-snapshot-isolated-database-cursor",
            PAGINATION_TRUSTED_DIFF_BLOCKER_78,
        ],
        "validation_evidence": [
            "api-pagination-response-emits-functional-priority-profile",
            "unit-test-asserts-cursor-profile-on-files-endpoint",
        ],
    }


def pagination_core_accuracy_gates(
    collection_name: str,
    *,
    total: int,
    returned: int,
    has_more: bool,
    pagination_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "cursor token emitted",
        "offset/limit/total recorded",
        "next/previous cursor support",
        "bounded row return",
        "snapshot isolation limitation warning",
        "pagination cursor manifest hash emitted",
        "page window id emitted",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted pagination cursor manifest diff pass")
    evidence_refs = [f"collection:{collection_name}", f"total:{total}", f"returned:{returned}", f"has_more:{has_more}"]
    if pagination_manifest:
        evidence_refs.append(f"manifest_hash:{pagination_manifest.get('manifest_hash', '')}")
        evidence_refs.append(f"page_window_id:{pagination_manifest.get('page_window_id', '')}")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("pagination cursor report-grade validation plan emitted")
        satisfied.append("pagination cursor report-grade ready slots emitted")
        evidence_refs.append(
            f"pagination_cursor_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256')}"
        )
        evidence_refs.append(f"pagination_cursor_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}")
        evidence_refs.append(
            f"pagination_cursor_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}"
        )
    return [
        build_accuracy_gate(
            78,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def ui_virtualization_metadata(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = [
        "web-ui-uses-bounded-row-windows-and-api-pagination-not-a-full-recycling-virtual-scroller",
        "viewport-persistence-and-keyboard-navigation-require-browser-e2e-validation",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79)
    row_window_manifest = build_ui_virtualization_manifest(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
    )
    functional_priority_profile = browser_e2e_performance_profile(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
    )
    validation_plan = build_ui_virtualization_report_grade_validation_plan(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
        row_window_manifest=row_window_manifest,
        trusted_diff=trusted_diff,
        performance_profile=functional_priority_profile,
    )
    return {
        "component": "ui-virtualization",
        "status": "bounded-visible-row-window",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "label": label,
        "total_rows": total,
        "visible_rows": visible,
        "api_pagination": api_pagination,
        "row_window_id": row_window_manifest["row_window_id"],
        "manifest_hash": row_window_manifest["manifest_hash"],
        "row_window_manifest": row_window_manifest,
        "functional_priority_profile": functional_priority_profile,
        "ui_virtualization_report_grade_validation_plan": validation_plan,
        "ui_virtualization_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "trusted_ui_virtualization_diff": dict(trusted_diff) if trusted_diff else missing_ui_virtualization_trusted_diff(),
        "core_accuracy_gates": ui_virtualization_core_accuracy_gates(
            label=label,
            total=total,
            visible=visible,
            api_pagination=api_pagination,
            row_window_manifest=row_window_manifest,
            trusted_diff=trusted_diff,
            validation_plan=validation_plan,
        ),
        "blockers": blockers,
    }


def build_ui_virtualization_manifest(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    row_limit: int = VIRTUAL_TABLE_ROW_LIMIT,
) -> dict[str, object]:
    row_window_core = {
        "label": label,
        "total_rows": max(0, int(total)),
        "visible_rows": max(0, int(visible)),
        "row_limit": max(0, int(row_limit)),
        "api_pagination": bool(api_pagination),
    }
    row_window_id = hashlib.sha256(json.dumps(row_window_core, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile": "ui-virtualization-manifest-v1",
        "profile_version": "ui-virtualization-manifest-v1",
        "item_number": 79,
        "row_window_id": row_window_id,
        **row_window_core,
        "viewport_state_policy": {
            "keyboard_navigation": True,
            "previous_next_controls": True,
            "persisted_viewport_restoration": False,
            "dom_recycling_virtual_scroller": False,
        },
        "bounded_dom_window": True,
        "client_windowing": True,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_ui_virtualization_report_grade_validation_plan(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    row_window_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    performance_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else missing_ui_virtualization_trusted_diff()
    performance_profile = performance_profile if isinstance(performance_profile, Mapping) else {}
    ready_slots = [
        {
            "slot": "row-window-manifest",
            "status": "ready",
            "evidence": row_window_manifest.get("manifest_hash", ""),
            "description": "Stable manifest hash binds the visible row window, row count, and pagination controls.",
        },
        {
            "slot": "visible-row-disclosure",
            "status": "ready",
            "evidence": f"{max(0, int(visible))}/{max(0, int(total))}",
            "description": "The UI/API discloses that only a bounded subset is rendered at once.",
        },
        {
            "slot": "bounded-dom-api-pagination-contract",
            "status": "ready",
            "evidence": f"api_pagination:{bool(api_pagination)}",
            "description": "Large result sets are navigated through API windows instead of a full DOM dump.",
        },
        {
            "slot": "keyboard-and-window-controls",
            "status": "ready",
            "evidence": json.dumps(row_window_manifest.get("viewport_state_policy", {}), sort_keys=True),
            "description": "Previous/next controls and keyboard navigation are part of the row-window contract.",
        },
        {
            "slot": "commercial-limitation-disclosure",
            "status": "ready",
            "evidence": "dom_recycling_virtual_scroller:false",
            "description": "The output explicitly prevents overstating bounded windows as a full recycling virtual scroller.",
        },
        {
            "slot": "functional-profile-linkage",
            "status": "ready",
            "evidence": performance_profile.get("component", "browser-e2e-performance-validation"),
            "description": "Browser E2E performance blockers are linked to the same virtualization evidence.",
        },
    ]
    blocking_slots = [
        {
            "slot": "trusted-browser-row-window-manifest",
            "status": "blocked",
            "blocker": UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79
            if trusted_diff.get("status") != "pass"
            else "trusted-diff-present-but-commercial-retest-required",
        },
        {
            "slot": "true-recycling-virtual-scroller",
            "status": "blocked",
            "blocker": "true-recycling-virtual-scroller-required",
        },
        {
            "slot": "persisted-viewport-restoration",
            "status": "blocked",
            "blocker": "persisted-viewport-restoration-required",
        },
        {
            "slot": "browser-e2e-100k-row-window-validation",
            "status": "blocked",
            "blocker": "browser-e2e-100k-row-window-validation-required",
        },
        {
            "slot": "browser-memory-profile",
            "status": "blocked",
            "blocker": "browser-memory-profile-required",
        },
        {
            "slot": "cross-client-virtualization-compatibility",
            "status": "blocked",
            "blocker": "cross-client-virtualization-compatibility-required",
        },
    ]
    plan_core = {
        "profile": UI_VIRTUALIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "profile_version": UI_VIRTUALIZATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 79,
        "gap_id": "#79",
        "label": label,
        "total_rows": max(0, int(total)),
        "visible_rows": max(0, int(visible)),
        "api_pagination": bool(api_pagination),
        "row_window_id": row_window_manifest.get("row_window_id", ""),
        "row_window_manifest_hash": row_window_manifest.get("manifest_hash", ""),
        "trusted_diff_status": trusted_diff.get("status", "missing"),
        "performance_profile_component": performance_profile.get("component", "browser-e2e-performance-validation"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "commercial_claim_allowed": False,
        "blockers": list(UI_VIRTUALIZATION_REPORT_GRADE_BLOCKERS),
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**plan_core, "validation_plan_sha256": validation_plan_sha256}


def browser_e2e_performance_profile(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    performance_contract_hash: str = "",
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_UI_BATCH_ID,
        "item_number": 25,
        "gap_id": "#25",
        "component": "browser-e2e-performance-validation",
        "status": "implemented-usable-browser-e2e-evidence-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "collection": label,
            "total_rows": total,
            "visible_rows": visible,
            "api_pagination": api_pagination,
            "bounded_dom_window_contract": visible <= max(total, visible),
            "large_table_supported_by_api_windowing": True,
            "browser_100k_record_e2e_attached": False,
            "performance_contract_hash": performance_contract_hash,
        },
        "blockers": [
            "browser-e2e-100k-record-run-not-attached",
            "browser-memory-profile-not-attached",
            "keyboard-navigation-viewport-persistence-e2e-not-attached",
        ],
        "recommended_actions": [
            "Run the browser e2e suite with a 100k+ row fixture before making commercial performance claims.",
            "Capture DOM node count, memory, p95 interaction latency, and screenshot evidence for the report package.",
        ],
        "validation_evidence": [
            "api-pagination-response-carries-bounded-visible-window",
            "unit-test-asserts-functional-priority-profile",
        ],
    }


def ui_virtualization_core_accuracy_gates(
    *,
    label: str,
    total: int,
    visible: int,
    api_pagination: bool,
    row_window_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    manifest = row_window_manifest or build_ui_virtualization_manifest(
        label=label,
        total=total,
        visible=visible,
        api_pagination=api_pagination,
    )
    satisfied = [
        "bounded DOM row window",
        "visible row count disclosed",
        "keyboard/filter workflow preserved",
        "UI row-window manifest hash emitted",
        "UI row-window id emitted",
        "true virtual scroller limitation warning",
    ]
    if api_pagination:
        satisfied.append("API pagination link preserved")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted UI virtualization manifest diff pass")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("UI virtualization report-grade validation plan emitted")
        satisfied.append("UI virtualization report-grade ready slots emitted")
    return [
        build_accuracy_gate(
            79,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"label:{label}",
                f"total_rows:{total}",
                f"visible_rows:{visible}",
                f"manifest_hash:{manifest.get('manifest_hash', '')}",
                f"row_window_id:{manifest.get('row_window_id', '')}",
                f"ui_virtualization_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"ui_virtualization_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"ui_virtualization_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
            ],
        )
    ]


def missing_pagination_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "blocker": PAGINATION_TRUSTED_DIFF_BLOCKER_78,
        "required_trusted_tools": sorted(PAGINATION_TRUSTED_TOOLS),
    }


def missing_ui_virtualization_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "blocker": UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
        "required_trusted_tools": sorted(UI_VIRTUALIZATION_TRUSTED_TOOLS),
    }


def build_ui_virtualization_trusted_diff(
    rapid_metadata: Mapping[str, object],
    trusted_metadata: Mapping[str, object],
    *,
    trusted_tool: str = "ui-virtualization-manifest",
) -> dict[str, object]:
    compared_fields = ["label", "total_rows", "visible_rows", "api_pagination", "row_window_id", "manifest_hash"]
    mismatches = [
        {"field": field, "rapid": rapid_metadata.get(field), "trusted": trusted_metadata.get(field)}
        for field in compared_fields
        if rapid_metadata.get(field) != trusted_metadata.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in UI_VIRTUALIZATION_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else UI_VIRTUALIZATION_TRUSTED_DIFF_BLOCKER_79,
    }


def resolve_commercial_readiness_validation_package(
    value: str | None,
    *,
    include_internal_validation: bool,
) -> Path | None:
    raw = str(value or "").strip()
    if include_internal_validation and not raw:
        if DEFAULT_INTERNAL_VALIDATION_PACKAGE.is_file():
            return DEFAULT_INTERNAL_VALIDATION_PACKAGE
        raise CommercialReadinessError(
            f"internal validation package is not present: {DEFAULT_INTERNAL_VALIDATION_PACKAGE}"
        )
    if not raw:
        return None
    if raw in {"internal", "default", "known-answer-001-120"}:
        if DEFAULT_INTERNAL_VALIDATION_PACKAGE.is_file():
            return DEFAULT_INTERNAL_VALIDATION_PACKAGE
        raise CommercialReadinessError(
            f"internal validation package is not present: {DEFAULT_INTERNAL_VALIDATION_PACKAGE}"
        )
    candidate = Path(raw).expanduser().resolve()
    if candidate.suffix.lower() != ".json":
        raise CommercialReadinessError("validation package must be a JSON file")
    if not candidate.is_file():
        raise CommercialReadinessError(f"validation package not found: {candidate}")
    return candidate


def commercial_readiness_validation_package_profile(path: Path | None) -> dict[str, object]:
    if path is None:
        return {
            "attached": False,
            "mode": "none",
            "path": "",
            "sha256": "",
            "warning": "No validation package is attached; validated maturity remains open.",
        }
    try:
        stat = path.stat()
        with path.open("rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
    except OSError as exc:
        return {
            "attached": False,
            "mode": "unreadable",
            "path": str(path),
            "sha256": "",
            "warning": f"Validation package could not be read: {exc}",
        }
    return {
        "attached": True,
        "mode": "internal-known-answer" if path == DEFAULT_INTERNAL_VALIDATION_PACKAGE else "custom",
        "path": str(path),
        "name": path.name,
        "size_bytes": stat.st_size,
        "sha256": digest,
        "warning": (
            "Internal fixture validation can satisfy validated maturity only; it does not allow commercial-grade claims."
            if path == DEFAULT_INTERNAL_VALIDATION_PACKAGE
            else "Custom validation package is attached; commercial-grade still depends on trusted diffs and blocker removal."
        ),
    }


def commercial_readiness_validation_package_mode(
    path: Path | None,
    *,
    include_internal_validation: bool,
) -> str:
    if path == DEFAULT_INTERNAL_VALIDATION_PACKAGE:
        return "internal-known-answer"
    if path is not None:
        return "custom"
    if include_internal_validation:
        return "internal-requested-missing"
    return "none"


def commercial_readiness_focus_item(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "number": item.get("number"),
        "title": item.get("title"),
        "category": item.get("category"),
        "severity": item.get("severity"),
        "status": item.get("status"),
        "highest_maturity_stage": item.get("highest_maturity_stage"),
        "next_required_gate": item.get("next_required_gate"),
        "remaining_gap": item.get("remaining_gap"),
        "next_action": item.get("next_internal_or_evidence_action") or item.get("next_action"),
        "commercial_blockers": list(item.get("commercial_blockers", []))
        if isinstance(item.get("commercial_blockers"), list)
        else [],
    }


def build_run_validation_source_integrity(summary: Mapping[str, object]) -> dict[str, object]:
    raw_root = summary.get("root") or summary.get("scan_scope_root")
    root = Path(str(raw_root)).expanduser().resolve() if raw_root else None
    result: dict[str, object] = {
        "path": str(root) if root else "",
        "exists": bool(root and root.exists()),
        "kind": "unknown",
        "hash_status": "not-computed",
        "hashes": {},
        "limitations": [],
    }
    if root is None:
        result["limitations"] = ["run summary does not include a source root"]
        return result
    if root.is_file():
        result["kind"] = "file"
        result["size"] = root.stat().st_size
        result["hashes"] = compute_hashes(root)
        result["hash_status"] = "computed"
    elif root.is_dir():
        result["kind"] = "directory"
        result["hash_status"] = "directory-hash-not-computed"
        result["limitations"] = [
            "source is a directory; whole-source hash requires acquisition manifest or file-level hash manifest"
        ]
    else:
        result["limitations"] = ["source path no longer exists at validation-package generation time"]
    source = summary.get("source")
    if isinstance(source, Mapping):
        result["source_metadata"] = {
            key: value
            for key, value in source.items()
            if key in {"input_kind", "analysis_root", "stage_dir", "workflow_status", "e01_metadata"}
        }
    return result


def build_run_validation_output_hashes(summary: Mapping[str, object], *, output_dir: Path) -> dict[str, object]:
    outputs = summary.get("outputs")
    rows: list[dict[str, object]] = []
    missing: list[dict[str, object]] = []
    if isinstance(outputs, Mapping):
        for name, raw_path in sorted(outputs.items()):
            path = Path(str(raw_path)).expanduser().resolve()
            row: dict[str, object] = {
                "name": str(name),
                "path": str(path),
                "inside_output_dir": is_relative_to(path, output_dir),
                "exists": path.is_file(),
            }
            if path.is_file():
                stat = path.stat()
                row["size"] = stat.st_size
                row["modified_at"] = dt_from_epoch(stat.st_mtime)
                row["hashes"] = compute_hashes(path)
                rows.append(row)
            else:
                row["hash_status"] = "missing"
                missing.append(row)
    return {
        "algorithm": ["md5", "sha1", "sha256"],
        "item_count": len(rows),
        "missing_count": len(missing),
        "items": rows,
        "missing": missing,
    }


def build_run_validation_review_status(case_path: Path) -> dict[str, object]:
    if not case_path.is_file():
        return {
            "exists": False,
            "case_path": str(case_path),
            "bookmark_count": 0,
            "report_item_count": 0,
            "review_status_counts": {},
            "limitations": ["case review file has not been created for this run"],
        }
    try:
        case_payload = load_case_payload(case_path)
    except (FileNotFoundError, CaseBookmarkError) as exc:
        return {
            "exists": False,
            "case_path": str(case_path),
            "error": str(exc),
            "limitations": ["case review file could not be loaded"],
        }
    summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}
    bookmarks = case_payload.get("bookmarks") if isinstance(case_payload.get("bookmarks"), list) else []
    return {
        "exists": True,
        "case_path": str(case_path),
        "case_id": case_payload.get("case_id"),
        "title": case_payload.get("title"),
        "bookmark_count": int(summary.get("bookmark_count") or len(bookmarks)),
        "report_item_count": int(summary.get("report_item_count") or 0),
        "review_revision_count": int(summary.get("review_revision_count") or 0),
        "review_status_counts": summary.get("review_status_counts") if isinstance(summary.get("review_status_counts"), Mapping) else {},
        "source_command_counts": summary.get("source_command_counts") if isinstance(summary.get("source_command_counts"), Mapping) else {},
        "bookmark_ids": [str(item.get("id") or "") for item in bookmarks if isinstance(item, Mapping)][:100],
    }


def build_run_validation_warning_inventory(summary: Mapping[str, object]) -> dict[str, object]:
    processing = summary.get("processing") if isinstance(summary.get("processing"), Mapping) else {}
    warnings = processing.get("warnings") if isinstance(processing.get("warnings"), list) else []
    steps = summary.get("steps") if isinstance(summary.get("steps"), list) else []
    parser_error_count = int(processing.get("parser_error_count") or 0)
    step_rows = []
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        step_rows.append(
            {
                "name": step.get("name"),
                "status": step.get("status"),
                "warning_level": step.get("warning_level"),
                "parser_error_count": int(step.get("parser_error_count") or 0),
                "output": step.get("output"),
            }
        )
    return {
        "warning_count": int(processing.get("warning_count") or len(warnings)),
        "highest_warning_level": processing.get("highest_warning_level"),
        "parser_error_count": parser_error_count,
        "warnings": warnings,
        "steps": step_rows,
    }


def build_run_validation_diff_inventory(summary: Mapping[str, object]) -> dict[str, object]:
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    diff_outputs = []
    for name, path in sorted(outputs.items()):
        if not any(token in str(name).lower() or token in str(path).lower() for token in ("diff", "trusted", "validation", "cross-tool")):
            continue
        resolved = Path(str(path)).expanduser().resolve()
        row: dict[str, object] = {
            "name": str(name),
            "path": str(path),
            "exists": resolved.is_file(),
        }
        if resolved.is_file():
            row["diff_summary"] = summarize_run_validation_diff_output(resolved)
        diff_outputs.append(row)
    state_replay_summaries = [
        summary
        for row in diff_outputs
        for summary in [row.get("diff_summary")]
        if isinstance(summary, Mapping) and summary.get("usn_state_replay_diff_present")
    ]
    return {
        "attached": bool(diff_outputs),
        "outputs": diff_outputs,
        "cross_tool_output_count": sum(
            1
            for row in diff_outputs
            if isinstance(row.get("diff_summary"), Mapping)
            and row["diff_summary"].get("command") == "cross-tool-validate"
        ),
        "usn_state_replay_diff_attached": bool(state_replay_summaries),
        "usn_state_replay_diff_pass_count": sum(
            1
            for summary in state_replay_summaries
            if summary.get("usn_state_replay_status") == "pass"
        ),
        "limitations": []
        if diff_outputs
        else ["no trusted-tool, cross-tool, or known-answer diff output is attached to this run"],
    }


def summarize_run_validation_diff_output(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {
            "read_status": "failed",
            "error": str(exc),
        }
    if not isinstance(payload, Mapping):
        return {
            "read_status": "unsupported-json-root",
        }
    comparisons = payload.get("comparisons") if isinstance(payload.get("comparisons"), list) else []
    field_diff_modes: list[str] = []
    usn_state_replay_present = False
    usn_state_replay_status = "not-attached"
    usn_state_replay_mismatch_count = 0
    usn_state_replay_common_record_count = 0
    for comparison in comparisons:
        if not isinstance(comparison, Mapping):
            continue
        for key, value in comparison.items():
            if not key.endswith("_field_comparison") or not isinstance(value, Mapping):
                continue
            mode = str(value.get("mode") or "")
            if mode:
                field_diff_modes.append(mode)
            if key == "usn_state_replay_field_comparison":
                usn_state_replay_present = True
                mismatch_count = int(value.get("mismatch_count") or 0)
                missing_count = int(value.get("missing_common_field_count") or 0)
                common_count = int(value.get("common_record_count") or 0)
                usn_state_replay_mismatch_count += mismatch_count
                usn_state_replay_common_record_count += common_count
                usn_state_replay_status = "pass" if common_count > 0 and mismatch_count == 0 and missing_count == 0 else "review-required"
    return {
        "read_status": "ok",
        "command": str(payload.get("command") or ""),
        "status": str(payload.get("status") or ""),
        "comparison_count": len(comparisons),
        "field_diff_modes": sorted(set(field_diff_modes)),
        "usn_state_replay_diff_present": usn_state_replay_present,
        "usn_state_replay_status": usn_state_replay_status,
        "usn_state_replay_common_record_count": usn_state_replay_common_record_count,
        "usn_state_replay_mismatch_count": usn_state_replay_mismatch_count,
    }


def build_run_validation_parser_execution(
    job_payload: Mapping[str, object],
    summary: Mapping[str, object],
) -> dict[str, object]:
    return {
        "job_steps": job_payload.get("steps") if isinstance(job_payload.get("steps"), list) else [],
        "run_steps": summary.get("steps") if isinstance(summary.get("steps"), list) else [],
        "tool_preflight": extract_tool_preflight(summary),
        "external_command_history": extract_external_command_history(summary),
        "parser_version_policy": {
            "rapidforensic_profile": "run-summary-stage-contract",
            "per-parser_version_capture": "partial",
            "limitation": "external parser binaries and native parser git revisions must be attached for report-defensible claims",
        },
    }


def build_run_validation_limitations(
    *,
    source_integrity: Mapping[str, object],
    output_hashes: Mapping[str, object],
    warning_inventory: Mapping[str, object],
    diff_inventory: Mapping[str, object],
    review_status: Mapping[str, object],
) -> list[dict[str, object]]:
    limitations: list[dict[str, object]] = []
    for message in source_integrity.get("limitations", []) if isinstance(source_integrity.get("limitations"), list) else []:
        limitations.append({"area": "source-integrity", "message": str(message)})
    if int(output_hashes.get("missing_count") or 0):
        limitations.append({"area": "output-hashes", "message": "one or more declared run outputs are missing"})
    if int(warning_inventory.get("parser_error_count") or 0):
        limitations.append({"area": "parser-execution", "message": "one or more parser stages reported isolated errors"})
    for message in diff_inventory.get("limitations", []) if isinstance(diff_inventory.get("limitations"), list) else []:
        limitations.append({"area": "trusted-diff", "message": str(message)})
    for message in review_status.get("limitations", []) if isinstance(review_status.get("limitations"), list) else []:
        limitations.append({"area": "review", "message": str(message)})
    limitations.append(
        {
            "area": "commercial-grade",
            "message": "this package is internally usable but still requires trusted-tool diffs, independent review, and operator-signed validation transcripts",
        }
    )
    return limitations


def source_viewer_actions(run_id: str, source_path: Path) -> list[dict[str, object]]:
    quoted_path = quote(str(source_path))
    return [
        {
            "id": "download",
            "label": "Open original source",
            "url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
            "purpose": "Open or download the authoritative file for manual verification.",
            "heavy": False,
        },
        {
            "id": "hash",
            "label": "Compute MD5/SHA1/SHA256",
            "url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "purpose": "Calculate submission-friendly hashes only when the analyst requests them.",
            "heavy": True,
        },
        {
            "id": "search-current-file",
            "label": "Search inside this file",
            "url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
            "purpose": "Run keyword search against the current file without re-searching the whole case.",
            "heavy": False,
        },
        {
            "id": "pin-compare",
            "label": "Pin for A/B/C compare",
            "url": None,
            "purpose": "Keep this file available while opening one or two more results for side-by-side review.",
            "heavy": False,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["compare"]],
            "max_pinned_items": 3,
        },
        {
            "id": "save-review",
            "label": "Save review decision",
            "url": None,
            "purpose": "Mark the result as relevant, rejected, needs-review, and optionally include it in reports.",
            "heavy": False,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["review"]],
            "status_fields": ["status", "verification_status", "reviewer", "assignee", "priority", "due_at", "include_in_report"],
        },
    ]


def archived_source_viewer_actions(run_id: str, archive_path: Path, display_path: str) -> list[dict[str, object]]:
    quoted_archive_path = quote(str(archive_path))
    quoted_display_path = quote(display_path)
    return [
        {
            "id": "download-container",
            "label": "Open original ZIP container",
            "url": f"/api/runs/{run_id}/source-file?path={quoted_archive_path}",
            "purpose": "Open or download the authoritative archive for manual verification.",
            "heavy": False,
        },
        {
            "id": "hash-container",
            "label": "Compute ZIP MD5/SHA1/SHA256",
            "url": f"/api/runs/{run_id}/source-metadata?path={quoted_archive_path}&hash=true",
            "purpose": "Calculate submission-friendly hashes for the original archive.",
            "heavy": True,
        },
        {
            "id": "search-current-entry",
            "label": "Search inside this ZIP entry",
            "url": f"/api/runs/{run_id}/source-search?path={quoted_display_path}",
            "purpose": "Search only the currently opened archive member without expanding the ZIP or re-searching the whole case.",
            "heavy": False,
            "source_preview_path": display_path,
        },
        {
            "id": "pin-compare",
            "label": "Pin entry for A/B/C compare",
            "url": None,
            "purpose": "Keep this ZIP entry available while opening one or two more results for side-by-side review.",
            "heavy": False,
            "source_preview_path": display_path,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["compare"]],
            "max_pinned_items": 3,
        },
        {
            "id": "save-review",
            "label": "Save review decision",
            "url": None,
            "purpose": "Mark the ZIP entry as relevant, rejected, needs-review, and optionally include it in reports.",
            "heavy": False,
            "source_preview_path": display_path,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["review"]],
            "status_fields": ["status", "verification_status", "reviewer", "assignee", "priority", "due_at", "include_in_report"],
        },
    ]


def source_review_workflow_metadata() -> dict[str, object]:
    satisfied = [
        "review status fields persisted",
        "assignment and priority captured",
        "verification status captured",
        "report inclusion state captured",
        "history/audit limitation warning",
    ]
    blockers = [
        "single-user-local-workflow-until-role-based-case-server-is-enabled",
        "review-decisions-still-require-source-hash-and-parser-limitation-verification",
        "review-workflow-trusted-audit-diff-required",
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=["source-preview:review_workflow", "case-db:review_mark", "case-db:review_mark_history"],
        )
    ]
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["review"]],
        "status": "implemented-baseline-validation-required",
        "supports": [
            "review-status",
            "verification-status",
            "reviewer",
            "assignee",
            "priority",
            "due-date",
            "include-in-report",
            "immutable-history",
        ],
        "ready_for_court_report": False,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
            item_number=51,
            component="reviewer-assignment-status-workflow",
            core_accuracy_gates=core_accuracy_gates,
            blockers=blockers,
            source_refs=["source-preview:review_workflow", "case-db:review_mark", "case-db:review_mark_history"],
            controls={
                "single_user_local_workflow": True,
                "assignment_fields_present": True,
                "audit_history_linked": True,
                "role_based_queue_enabled": False,
                "notification_sla_enabled": False,
            },
        ),
        "blockers": blockers,
    }


def source_review_evidence_tray_profile(*, run_id: str, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    sidecar_contract = source_evidence_tray_sidecar_contract(run_id=run_id, source_path=source_path)
    return {
        "profile_version": "review-evidence-tray-profile-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 19,
        "qc_prep_item": 13,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "tray_item_contract": {
            "source_path": True,
            "source_name": True,
            "review_status": True,
            "verification_status": True,
            "tags": True,
            "note": True,
            "include_in_report": True,
            "citation_or_locator": True,
        },
        "sidecar_viewer_contract": sidecar_contract,
        "sidecar_viewer_contract_hash": stable_payload_sha256(sidecar_contract),
        "default_review_states": ["unreviewed", "needs-review", "relevant", "not-relevant", "excluded"],
        "default_verification_states": ["unverified", "source_opened", "hash_verified", "cross_tool_verified"],
        "source_actions": {
            "save_review": "POST /api/runs/{run_id}/bookmarks",
            "hash_source": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "search_current_file": f"/api/runs/{run_id}/source-search?path={quoted_path}",
        },
        "reportability_decision": {
            "decision": "do-not-export-review-tray-as-final-report-without-hash-and-citation",
            "allowed_use": "single-case-review-selection-and-report-staging",
            "required_before_report": [
                "mark include_in_report intentionally",
                "verify source hash or explain limitation",
                "preserve citation/locator and analyst note",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "role-based-review-queue-not-enabled",
            "multi-user-conflict-resolution-required",
            "review-tray-audit-diff-required",
        ],
    }


def source_evidence_tray_sidecar_contract(*, run_id: str, source_path: Path) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    quoted_path = quote(str(source_path))
    links: list[dict[str, object]] = []
    if mime_type.startswith("image/"):
        links.extend(
            [
                {
                    "id": "image-gallery",
                    "label": "Image gallery / similarity",
                    "viewer": "source-image-gallery",
                    "url": f"/api/runs/{run_id}/source-image-gallery?path={quoted_path}",
                    "sidecar_type": "nearby-image-review",
                },
                {
                    "id": "ocr-queue",
                    "label": "OCR queue",
                    "viewer": "source-ocr-queue",
                    "url": f"/api/runs/{run_id}/source-ocr-queue?path={quoted_path}",
                    "sidecar_type": "ocr-work-queue",
                },
                {
                    "id": "ocr-translation",
                    "label": "OCR / translation review",
                    "viewer": "source-ocr-translation",
                    "url": f"/api/runs/{run_id}/source-ocr-translation?path={quoted_path}",
                    "sidecar_type": "ocr-translation-sidecar",
                },
            ]
        )
    if mime_type.startswith(("audio/", "video/")):
        links.append(
            {
                "id": "media-cue",
                "label": "Transcript cue package",
                "viewer": "source-media-cue",
                "url": f"/api/runs/{run_id}/source-media-cue?path={quoted_path}&sidecar_index=1&cue_index=1",
                "sidecar_type": "media-transcript-cue",
            }
        )
    if suffix in {".eml", ".mbox"}:
        links.append(
            {
                "id": "email-attachment",
                "label": "Email attachment package",
                "viewer": "source-email-attachment",
                "url": f"/api/runs/{run_id}/source-email-attachment?path={quoted_path}&message_index=1&attachment_index=1",
                "sidecar_type": "email-attachment",
            }
        )
    return {
        "profile_version": "evidence-tray-sidecar-viewer-contract-v1",
        "qc_prep_item": 13,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "viewer_family_hint": source_viewer_family(source_path, suffix=suffix, mime_type=mime_type),
        "sidecar_link_count": len(links),
        "sidecar_links": links,
        "supports_sidecar_selection": bool(links),
        "supports_report_candidate_promotion": True,
        "required_before_report": [
            "open sidecar viewer package",
            "verify source hash or sidecar hash",
            "save analyst review note",
            "mark include_in_report intentionally",
        ],
        "commercial_grade_blockers": [
            "browser-e2e-sidecar-tray-selection-required",
            "trusted-sidecar-rendering-diff-required",
        ],
    }


def source_compare_workflow_metadata() -> dict[str, object]:
    blockers = [
        "binary-structure-aware-diff-not-implemented",
        "visual-diff-and-table-aware-diff-require-dedicated-viewers",
        "compare-trusted-expected-diff-required",
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            52,
            satisfied_checks=[
                "A/B/C baseline compare",
                "hash comparison",
                "bounded text diff",
                "status counts",
                "specialized diff limitation warning",
            ],
            evidence_refs=["source-preview:compare_workflow", "command:compare"],
        )
    ]
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["compare"]],
        "status": "implemented-baseline-validation-required",
        "supports": ["a-b-compare", "a-b-c-baseline-compare", "hash-compare", "bounded-text-diff", "report-pivot"],
        "ready_for_court_report": False,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
            item_number=52,
            component="source-preview-compare-workflow",
            core_accuracy_gates=core_accuracy_gates,
            blockers=blockers,
            source_refs=["source-preview:compare_workflow", "command:compare"],
            controls={
                "max_pinned_items": 3,
                "a_b_c_baseline_compare": True,
                "bounded_text_diff": True,
                "persistent_compare_notes": False,
                "binary_structure_aware_diff": False,
            },
        ),
        "blockers": blockers,
    }


def source_compare_pin_profile(*, run_id: str, source_path: Path) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    return {
        "profile_version": "source-compare-pin-profile-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 20,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "max_pinned_items": 3,
        "pin_contract": {
            "path": True,
            "name": True,
            "viewer_family": True,
            "source_hash_optional": True,
            "source_search_citation_optional": True,
            "analyst_note_required_before_report": True,
        },
        "compare_actions": {
            "open_source": f"/api/runs/{run_id}/source-file?path={quoted_path}",
            "preview_source": f"/api/runs/{run_id}/source-preview?path={quoted_path}",
            "hash_source": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
        },
        "supported_comparison_modes": [
            "metadata-side-by-side",
            "hash-comparison",
            "bounded-text-diff",
            "source-search-snippet-compare",
        ],
        "unsupported_comparison_modes": [
            "semantic-binary-diff",
            "sqlite-row-aware-diff",
            "image-visual-diff",
            "email-thread-semantic-diff",
        ],
        "reportability_decision": {
            "decision": "do-not-report-compare-selection-without-persistent-note-and-source-citation",
            "allowed_use": "analyst-side-by-side-review-pivot",
            "required_before_report": [
                "save analyst comparison rationale",
                "verify source hashes for selected items",
                "cite each compared source or search locator",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "persistent-compare-notes-not-yet-implemented",
            "binary-table-visual-diff-not-yet-implemented",
            "compare-trusted-expected-diff-required",
        ],
    }


def source_analyst_workbench_profile(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    viewer_family = source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)
    stage10_matrix = source_stage10_capability_matrix(
        run_id=run_id,
        source_path=source_path,
        quoted_path=quoted_path,
        viewer_family=viewer_family,
    )
    return {
        "profile_version": "analyst-workbench-source-review-v1",
        "commercial_batch_id": "commercial-uplift-051-060",
        "item_numbers": list(range(51, 61)),
        "source_path": str(source_path),
        "viewer_family": viewer_family,
        "workflow_contract": {
            "current_file_search": {
                "implemented": True,
                "supporting_capability": "current-file-verification-search",
                "url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
                "bounded": True,
            },
            "specialized_viewer": {
                "implemented": True,
                "item_number": stage10_viewer_item_number(viewer_family),
                "viewer_family": viewer_family,
                "metadata_hidden_by_default": True,
                "max_inline_text_chars": max_chars,
                "specialization_profile": "source-viewer-specialization-v1",
            },
            "review_board": {
                "implemented": True,
                "item_number": 51,
                "fields": ["status", "verification_status", "tags", "note", "assignee", "priority", "include_in_report"],
            },
            "compare_workflow": {
                "implemented": True,
                "item_number": 52,
                "max_pinned_items": 3,
                "supports": ["A/B/C pinned evidence", "bounded text diff", "hash comparison"],
            },
            "hex_viewer": {
                "implemented": True,
                "item_number": 53,
                "available_when": "binary-or-large-text-fallback",
            },
            "sqlite_viewer": {
                "implemented": viewer_family == "sqlite-table-preview",
                "item_number": 54,
                "endpoint": "/api/runs/{run_id}/source-sqlite-table",
            },
            "email_viewer": {
                "implemented": viewer_family == "email-thread-preview",
                "item_number": 55,
                "endpoint": "/api/runs/{run_id}/source-email-attachment",
            },
            "image_gallery": {
                "implemented": viewer_family == "image-gallery-preview",
                "item_number": 56,
                "endpoint": "/api/runs/{run_id}/source-image-gallery",
            },
            "media_transcript": {
                "implemented": viewer_family == "media-preview",
                "item_number": 57,
                "endpoint": "/api/runs/{run_id}/source-media-cue",
            },
            "ocr_queue": {
                "implemented": True,
                "item_number": 58,
                "endpoint": "/api/runs/{run_id}/source-ocr-queue",
            },
            "korean_ocr_translation": {
                "implemented": True,
                "item_number": 59,
                "endpoint": "/api/runs/{run_id}/source-ocr-translation",
            },
            "dedup_review": {
                "implemented": True,
                "item_number": 60,
                "source": "analysis_analyst_review_profile.dedup_review",
            },
        },
        "stage10_capability_matrix": stage10_matrix,
        "stage10_capability_matrix_hash": stable_payload_sha256(stage10_matrix),
        "large_data_controls": {
            "inline_preview_bounded": True,
            "structured_preview_max_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
            "hex_preview_max_bytes": HEX_PREVIEW_MAX_BYTES,
            "full_file_download_is_explicit_action": True,
            "large_result_navigation": "cursor-or-bounded-preview-required",
            "dedup_collapse_expected": True,
        },
        "reportability_decision": {
            "decision": "review-workbench-output-requires-source-citation-before-report",
            "allowed_use": "single-case-source-verification-workbench",
            "required_before_report": [
                "save review decision for report candidates",
                "compute source hash where needed",
                "preserve citation, locator, and parser/viewer limitation",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-workbench-validation-required",
            "persistent-compare-notes-not-yet-implemented",
            "role-based-review-server-not-yet-implemented",
            "trusted-viewer-and-dedup-corpus-required",
        ],
    }


def stage10_viewer_item_number(viewer_family: str) -> int:
    return STAGE10_VIEWER_ITEM_BY_FAMILY.get(viewer_family, 53)


def source_stage10_capability_matrix(
    *,
    run_id: str,
    source_path: Path,
    quoted_path: str,
    viewer_family: str,
) -> dict[str, object]:
    """Expose the #51-#60 review/viewer workbench as one UI contract."""
    entries = [
        stage10_capability_entry_from_spec(
            spec,
            run_id=run_id,
            quoted_path=quoted_path,
            viewer_family=viewer_family,
        )
        for spec in STAGE10_CAPABILITY_SPECS
    ]
    implemented_count = sum(1 for entry in entries if entry["implemented"])
    primary_count = sum(1 for entry in entries if entry["primary_for_current_source"])
    return {
        "profile_version": "stage10-review-viewer-capability-matrix-v1",
        "commercial_batch_id": "commercial-uplift-051-060",
        "source_path": str(source_path),
        "source_name": source_path.name,
        "viewer_family": viewer_family,
        "implemented_count": implemented_count,
        "primary_for_current_source_count": primary_count,
        "capability_count": len(entries),
        "entries": entries,
        "reportability_decision": {
            "decision": "do-not-claim-stage10-commercial-grade-without-trusted-viewer-corpora",
            "allowed_use": "single-case-review-viewer-navigation-contract",
            "required_before_report": [
                "save review mark and source locator",
                "compute source hash or record why not",
                "attach viewer-specific citation manifest",
                "disclose unsupported native recovery or corpus gaps",
            ],
        },
    }


def stage10_capability_entry_from_spec(
    spec: Mapping[str, object],
    *,
    run_id: str,
    quoted_path: str,
    viewer_family: str,
) -> dict[str, object]:
    route_template = spec.get("route_template")
    route = (
        str(route_template).format(run_id=run_id, quoted_path=quoted_path)
        if isinstance(route_template, str)
        else None
    )
    primary_families = spec.get("primary_families")
    primary = isinstance(primary_families, tuple) and viewer_family in primary_families
    return stage10_capability_entry(
        int(spec["item_number"]),
        str(spec["label"]),
        implemented=True,
        primary=primary,
        route=route,
        evidence_refs=tuple(str(item) for item in spec.get("evidence_refs", ())),
        blockers=tuple(str(item) for item in spec.get("blockers", ())),
    )


def stage10_capability_entry(
    item_number: int,
    label: str,
    *,
    implemented: bool,
    primary: bool,
    route: str | None,
    evidence_refs: Sequence[str],
    blockers: Sequence[str],
) -> dict[str, object]:
    return {
        "item_number": item_number,
        "gap_id": f"#{item_number}",
        "label": label,
        "implemented": implemented,
        "primary_for_current_source": primary,
        "route": route,
        "evidence_refs": list(evidence_refs),
        "commercial_grade_ready": False,
        "commercial_blockers": list(blockers),
    }


def build_workbench_smoke_contract() -> dict[str, object]:
    required_steps = [
        {
            "id": "open-workbench",
            "action": "GET /",
            "selector": WORKBENCH_SMOKE_SELECTORS["shell"],
            "assertion": "Analyst console shell is visible and API health can be checked.",
        },
        {
            "id": "create-or-import-run",
            "action": "POST /api/sample-case/run or POST /api/runs/import",
            "selector": WORKBENCH_SMOKE_SELECTORS["sample_run"],
            "assertion": "A completed run appears in the run list.",
        },
        {
            "id": "select-run",
            "action": "GET /api/runs/{run_id}",
            "selector": WORKBENCH_SMOKE_SELECTORS["case_hero"],
            "assertion": "Case hero, readiness dashboard, artifact navigator, and validation summary are rendered.",
        },
        {
            "id": "search-case",
            "action": "GET /api/runs/{run_id}/search",
            "selector": WORKBENCH_SMOKE_SELECTORS["global_search"],
            "assertion": "Global search opens the Find view and returns bounded results.",
        },
        {
            "id": "open-source-viewer",
            "action": "GET /api/runs/{run_id}/source-preview?path=...",
            "selector": WORKBENCH_SMOKE_SELECTORS["source_viewer"],
            "assertion": "Source viewer opens with source-verification trail and bounded preview metadata.",
        },
        {
            "id": "mark-evidence",
            "action": "POST /api/runs/{run_id}/bookmarks",
            "selector": WORKBENCH_SMOKE_SELECTORS["viewer_review"],
            "assertion": "Review status, tags, notes, and include-in-report decision can be saved.",
        },
        {
            "id": "export-report",
            "action": "GET /api/runs/{run_id}/case-report/file",
            "selector": WORKBENCH_SMOKE_SELECTORS["report_tab"],
            "assertion": "Report view and report export endpoint are reachable after review marking.",
        },
    ]
    platform_evidence = [
        {
            "platform": "windows",
            "script": "scripts/windows/smoke-test-rapidtriage.ps1",
            "summary_json": "rapidtriage-windows-smoke/smoke-summary.json",
            "summary_markdown": "rapidtriage-windows-smoke/smoke-summary.md",
            "contract_json": "rapidtriage-windows-smoke/workbench-smoke-contract.json",
            "required_fresh_host": "Fresh Windows 11 workstation or VM",
            "status": "external-evidence-required",
        },
        {
            "platform": "macos",
            "script": "scripts/smoke-test-rapidtriage.sh --output-dir rapidtriage-macos-smoke",
            "summary_json": "rapidtriage-macos-smoke/smoke-summary.json",
            "summary_markdown": "rapidtriage-macos-smoke/smoke-summary.md",
            "contract_json": "rapidtriage-macos-smoke/workbench-smoke-contract.json",
            "required_fresh_host": "Fresh macOS workstation or VM",
            "status": "external-evidence-required",
        },
    ]
    payload = {
        "command": "workbench.smoke-contract",
        "profile_version": WORKBENCH_SMOKE_CONTRACT_VERSION,
        "qc_prep_item": 5,
        "immediate_queue_item": 7,
        "status": "implemented-browser-e2e-evidence-required",
        "browser_test_ready": True,
        "selectors": WORKBENCH_SMOKE_SELECTORS,
        "required_steps": required_steps,
        "platform_evidence": platform_evidence,
        "fresh_gui_launch_evidence": {
            "profile_version": "fresh-gui-launch-smoke-evidence-v1",
            "required_platforms": ["windows", "macos"],
            "required_outputs": [
                "smoke-summary.json",
                "smoke-summary.md",
                "workbench-smoke-contract.json",
                "web-index.html or browser screenshot",
                "web-server.log",
            ],
            "required_assertions": [
                "web server returns HTTP 200",
                "workbench shell selector is present",
                "sample or imported run reaches summary",
                "source viewer and review selectors are present",
                "report/export path is reachable",
            ],
            "commercial_claim_allowed_without_external_runs": False,
        },
        "api_routes": {
            "open_workbench": "/",
            "health": "/api/health",
            "sample_case": "/api/sample-case/run",
            "runs": "/api/runs",
            "run_detail": "/api/runs/{run_id}",
            "search": "/api/runs/{run_id}/search",
            "source_preview": "/api/runs/{run_id}/source-preview?path={path}",
            "bookmark": "/api/runs/{run_id}/bookmarks",
            "case_report": "/api/runs/{run_id}/case-report/file",
        },
        "implemented_controls": {
            "stable_selectors": True,
            "sample_case_bootstrap": True,
            "existing_run_import": True,
            "source_viewer_contract": True,
            "review_mark_contract": True,
            "report_export_contract": True,
            "platform_smoke_scripts": True,
            "smoke_contract_artifact": True,
            "browser_e2e_attached": False,
        },
        "functional_priority_profile": {
            "queue_item_number": 7,
            "batch_id": "functional-priority-001-010",
            "component": "single-case-workbench-browser-smoke",
            "status": "implemented-usable-validation-required",
            "selector_count": len(WORKBENCH_SMOKE_SELECTORS),
            "required_step_count": len(required_steps),
            "passed_validation_check_ids": [
                "stable-workbench-selectors-defined",
                "sample-case-smoke-route-defined",
                "source-viewer-review-report-flow-defined",
            ],
            "failed_validation_check_ids": [
                "playwright-browser-smoke-log-not-attached",
                "screenshot-evidence-not-attached",
                "fresh-windows-browser-run-not-attached",
                "fresh-macos-browser-run-not-attached",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-smoke-log-not-attached",
            "visual-regression-screenshot-not-attached",
            "fresh-windows-11-browser-smoke-required",
            "fresh-macos-browser-smoke-required",
        ],
    }
    payload["manifest_sha256"] = stable_payload_sha256(payload)
    return payload


def build_workbench_large_result_evidence(*, record_count: int) -> dict[str, object]:
    total = max(1, int(record_count))
    visible = min(total, VIRTUAL_TABLE_ROW_LIMIT)
    offsets = sorted({0, min(VIRTUAL_TABLE_ROW_LIMIT, max(0, total - visible)), max(0, total - visible)})
    window_manifests = [
        {
            "window_name": f"search-window-{index + 1}",
            "offset": offset,
            "start_row": offset + 1,
            "end_row": min(total, offset + visible),
            "manifest": build_ui_virtualization_manifest(
                label=f"synthetic-100k-search-window-{index + 1}",
                total=total,
                visible=visible,
                api_pagination=True,
            ),
        }
        for index, offset in enumerate(offsets)
    ]
    max_dom_rows = visible
    estimated_dom_nodes = max_dom_rows * 8
    dom_budget = 5_000
    latency_budget_ms = 500
    memory_budget_mb = 512
    performance_contract = build_browser_e2e_performance_contract(
        total=total,
        visible=visible,
        dom_budget=dom_budget,
        latency_budget_ms=latency_budget_ms,
        memory_budget_mb=memory_budget_mb,
        window_manifests=window_manifests,
    )
    profile = browser_e2e_performance_profile(
        label="synthetic-large-result-workbench",
        total=total,
        visible=visible,
        api_pagination=True,
        performance_contract_hash=str(performance_contract["contract_hash"]),
    )
    evidence_manifest = build_large_result_evidence_manifest(
        total=total,
        visible=visible,
        window_manifests=window_manifests,
        performance_contract=performance_contract,
        estimated_dom_nodes=estimated_dom_nodes,
        dom_budget=dom_budget,
        latency_budget_ms=latency_budget_ms,
        memory_budget_mb=memory_budget_mb,
    )
    return {
        "command": "workbench.large-result-evidence",
        "profile_version": "large-result-ui-evidence-v1",
        "immediate_queue_item": 8,
        "status": "synthetic-ui-window-proof-browser-run-required",
        "record_count": total,
        "row_limit": VIRTUAL_TABLE_ROW_LIMIT,
        "visible_rows": visible,
        "window_count": len(window_manifests),
        "window_manifests": window_manifests,
        "dom_budget": {
            "max_dom_rows": max_dom_rows,
            "estimated_dom_nodes": estimated_dom_nodes,
            "dom_node_budget": dom_budget,
            "dom_budget_pass": estimated_dom_nodes <= dom_budget,
            "reason": "The UI renders a bounded row window instead of all synthetic records.",
        },
        "search_latency_budget": {
            "target_p95_ms": latency_budget_ms,
            "synthetic_browser_latency_attached": False,
            "api_pagination_required": True,
            "case_db_or_cursor_endpoint_required": True,
        },
        "memory_budget": {
            "target_max_heap_mb": memory_budget_mb,
            "synthetic_browser_memory_attached": False,
            "heap_snapshot_required": True,
        },
        "performance_contract": performance_contract,
        "evidence_manifest": evidence_manifest,
        "evidence_manifest_hash": evidence_manifest["manifest_hash"],
        "implemented_controls": {
            "synthetic_100k_contract": total >= 100_000,
            "cursor_window_manifest": True,
            "bounded_dom_row_window": visible <= VIRTUAL_TABLE_ROW_LIMIT,
            "viewport_offset_persistence": True,
            "keyboard_window_navigation": True,
            "browser_e2e_contract": True,
            "performance_budget_manifest": True,
            "browser_trace_attached": False,
        },
        "functional_priority_profile": {
            **profile,
            "queue_item_number": 8,
            "status": "implemented-synthetic-proof-browser-e2e-required",
            "controls": {
                **profile["controls"],
                "synthetic_record_count": total,
                "dom_budget_pass": estimated_dom_nodes <= dom_budget,
                "window_manifest_count": len(window_manifests),
                "performance_contract_hash": performance_contract["contract_hash"],
                "evidence_manifest_hash": evidence_manifest["manifest_hash"],
                "target_p95_interaction_ms": latency_budget_ms,
                "target_max_heap_mb": memory_budget_mb,
            },
            "failed_validation_check_ids": [
                "playwright-100k-browser-trace-not-attached",
                "browser-memory-profile-not-attached",
                "real-case-search-latency-not-attached",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "actual-browser-100k-run-required",
            "memory-profile-and-p95-latency-required",
            "fresh-windows-11-large-result-smoke-required",
        ],
    }


def build_browser_e2e_performance_contract(
    *,
    total: int,
    visible: int,
    dom_budget: int,
    latency_budget_ms: int,
    memory_budget_mb: int,
    window_manifests: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    contract_core = {
        "profile_version": BROWSER_E2E_PERFORMANCE_CONTRACT_VERSION,
        "item_number": 25,
        "gap_id": "#25",
        "target_record_count": total,
        "visible_row_limit": visible,
        "selectors": {
            "workbench_shell": WORKBENCH_SMOKE_SELECTORS["shell"],
            "detail_panel": WORKBENCH_SMOKE_SELECTORS["detail_panel"],
            "global_search": WORKBENCH_SMOKE_SELECTORS["global_search"],
            "search_view": WORKBENCH_SMOKE_SELECTORS["search_view"],
            "source_viewer": WORKBENCH_SMOKE_SELECTORS["source_viewer"],
            "virtual_window_card": ".virtual-window-card",
            "virtual_window_next": "[data-virtual-window-key]",
            "virtual_window_jump": "[data-virtual-window-jump-key]",
        },
        "required_steps": [
            {
                "id": "load-workbench",
                "action": "open / and wait for workbench shell",
                "measurement": "initial render time",
                "pass_criteria": f"shell visible and DOM nodes <= {dom_budget}",
            },
            {
                "id": "load-large-result-json",
                "action": "open /api/workbench/large-result-evidence?record_count=100000 and store response",
                "measurement": "contract/evidence manifest hash captured",
                "pass_criteria": "response includes performance_contract.contract_hash and evidence_manifest_hash",
            },
            {
                "id": "render-windowed-table",
                "action": "render or navigate to a result table with a bounded virtual window",
                "measurement": "mounted row count and DOM node count",
                "pass_criteria": f"mounted rows <= {visible} and DOM nodes <= {dom_budget}",
            },
            {
                "id": "keyboard-window-navigation",
                "action": "use next/previous/jump controls and keyboard shortcuts for at least three windows",
                "measurement": "p95 interaction latency",
                "pass_criteria": f"p95 interaction latency <= {latency_budget_ms} ms",
            },
            {
                "id": "source-viewer-roundtrip",
                "action": "open a source viewer from a large result and return to the same viewport",
                "measurement": "viewport persistence and heap growth",
                "pass_criteria": f"viewport restored and heap <= {memory_budget_mb} MB",
            },
            {
                "id": "attach-evidence",
                "action": "attach Playwright trace, screenshot, DOM count, memory profile, and latency samples",
                "measurement": "external evidence completeness",
                "pass_criteria": "all required artifacts are present before commercial performance claim",
            },
        ],
        "performance_budgets": {
            "dom_node_budget": dom_budget,
            "mounted_row_budget": visible,
            "target_p95_interaction_ms": latency_budget_ms,
            "target_max_heap_mb": memory_budget_mb,
        },
        "required_artifacts": [
            "playwright-trace.zip",
            "large-table-screenshot.png",
            "dom-node-count.json",
            "memory-profile.json",
            "interaction-latency-samples.json",
            "fresh-windows-11-run-transcript.txt",
        ],
        "window_manifest_hashes": [
            str(item.get("manifest", {}).get("manifest_hash"))
            for item in window_manifests
            if isinstance(item.get("manifest"), Mapping)
        ],
        "commercial_claim_allowed": False,
        "blockers": [
            "playwright-100k-browser-trace-not-attached",
            "browser-memory-profile-not-attached",
            "fresh-windows-11-large-result-smoke-required",
        ],
    }
    return {**contract_core, "contract_hash": hashlib.sha256(json.dumps(contract_core, sort_keys=True).encode("utf-8")).hexdigest()}


def build_large_result_evidence_manifest(
    *,
    total: int,
    visible: int,
    window_manifests: Sequence[Mapping[str, object]],
    performance_contract: Mapping[str, object],
    estimated_dom_nodes: int,
    dom_budget: int,
    latency_budget_ms: int,
    memory_budget_mb: int,
) -> dict[str, object]:
    manifest_core = {
        "profile_version": "large-result-ui-evidence-manifest-v1",
        "item_number": 25,
        "record_count": total,
        "visible_rows": visible,
        "estimated_dom_nodes": estimated_dom_nodes,
        "dom_budget": dom_budget,
        "dom_budget_pass": estimated_dom_nodes <= dom_budget,
        "latency_budget_ms": latency_budget_ms,
        "memory_budget_mb": memory_budget_mb,
        "performance_contract_hash": str(performance_contract.get("contract_hash") or ""),
        "window_manifest_hashes": [
            str(item.get("manifest", {}).get("manifest_hash"))
            for item in window_manifests
            if isinstance(item.get("manifest"), Mapping)
        ],
        "internal_evidence_status": "synthetic-contract-generated",
        "external_evidence_status": "missing",
        "commercial_gap_ids": ["#25", VIEWER_WORKFLOW_GAP_IDS["ui_virtualization"]],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()}


def source_viewer_family(source_path: Path, *, suffix: str, mime_type: str) -> str:
    if mime_type.startswith("image/"):
        return "image-gallery-preview"
    if is_sqlite_candidate(source_path, suffix):
        return "sqlite-table-preview"
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return "json-structured-preview"
    if suffix == ".xml":
        return "xml-structured-preview"
    if suffix in {".eml", ".mbox"}:
        return "email-thread-preview"
    if mime_type.startswith(("audio/", "video/")):
        return "media-preview"
    if suffix in SUPPORTED_DOC_EXTS:
        return "document-text-preview"
    return "text-or-hex-preview"


def source_viewer_specialization_profile(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
) -> dict[str, object]:
    viewer_family = source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)
    quoted_path = quote(str(source_path))
    return {
        "profile_version": "source-viewer-specialization-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 18,
        "viewer_family": viewer_family,
        "source_path": str(source_path),
        "default_layout": {
            "primary_content_first": True,
            "metadata_collapsed_by_default": True,
            "limitations_visible": True,
            "review_controls_visible": True,
            "compare_pin_visible": True,
        },
        "supported_viewer_features": source_viewer_feature_matrix(viewer_family),
        "citation_contract": {
            "source_path": True,
            "source_name": True,
            "viewer_family": True,
            "search_inside_file_url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
            "metadata_hash_url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}&hash=true",
            "download_url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
        },
        "large_data_controls": {
            "inline_text_limit": max_chars,
            "structured_preview_max_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
            "hex_preview_max_bytes": HEX_PREVIEW_MAX_BYTES,
            "explicit_full_file_open": True,
            "active_content_blocked": True,
        },
        "reportability_decision": {
            "decision": "do-not-report-viewer-rendering-without-source-citation",
            "allowed_use": "source-viewer-verification-and-review",
            "required_before_report": [
                "capture source hash where needed",
                "preserve source-search locator or table/offset citation",
                "record analyst review status and limitation wording",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-visual-validation-required",
            "large-preview-corpus-required",
            "trusted-viewer-rendering-diff-required",
        ],
    }


def source_viewer_feature_matrix(viewer_family: str) -> dict[str, bool]:
    return {
        "text_preview": viewer_family in {"document-text-preview", "text-or-hex-preview"},
        "hex_preview": viewer_family == "text-or-hex-preview",
        "sqlite_table_preview": viewer_family == "sqlite-table-preview",
        "json_tree_preview": viewer_family == "json-structured-preview",
        "xml_tree_preview": viewer_family == "xml-structured-preview",
        "image_preview": viewer_family == "image-gallery-preview",
        "media_metadata_preview": viewer_family == "media-preview",
        "email_thread_preview": viewer_family == "email-thread-preview",
        "current_file_search": True,
        "source_hash_on_demand": True,
        "metadata_collapsible": True,
        "review_and_compare_actions": True,
    }


def viewer_workflow_commercial_uplift_evidence(
    *,
    item_number: int,
    component: str,
    core_accuracy_gates: Sequence[Mapping[str, object]],
    blockers: Sequence[str],
    source_refs: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == gap_id:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-051-055",
        "item_numbers": [item_number],
        "implementation_track": component,
        "source_refs": list(source_refs),
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=item_number,
            component=component,
            blockers=blockers,
            controls=controls,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": list(blockers),
        "commercial_blockers": list(blockers),
        "large_data_controls": dict(controls),
        "reporting_status": "implemented-baseline-validation-required",
    }


def viewer_workflow_reportability_decision(
    *,
    item_number: int,
    component: str,
    blockers: Sequence[str],
    controls: Mapping[str, object],
) -> dict[str, object]:
    gap_id = f"#{item_number}"
    allowed_uses = {
        51: "single-user-review-status-triage-pivot",
        52: "bounded-file-compare-triage-pivot",
        53: "bounded-hex-preview-triage-pivot",
        54: "read-only-sqlite-preview-triage-pivot",
        55: "bounded-email-conversation-triage-pivot",
        56: "image-gallery-metadata-triage-pivot",
        57: "media-transcript-sidecar-triage-pivot",
    }
    decisions = {
        51: "do-not-report-review-workflow-as-role-based-case-management",
        52: "do-not-report-compare-output-as-semantic-diff-complete",
        53: "do-not-report-hex-preview-as-full-source-byte-citation",
        54: "do-not-report-sqlite-preview-as-deleted-row-or-wal-complete",
        55: "do-not-report-email-preview-as-native-mailbox-thread-complete",
        56: "do-not-report-image-gallery-as-ml-or-sensitive-media-complete",
        57: "do-not-report-media-preview-as-playback-or-asr-validated",
    }
    required = {
        51: [
            "enable role-based multi-user queues, conflict handling, notifications, and signed reviewer SOPs",
            "verify source hashes and parser limitations before report inclusion",
        ],
        52: [
            "add semantic binary/image/SQLite/mailbox diff viewers and persistent analyst comparison notes",
            "attach reviewed selection rationale for each compared evidence item",
        ],
        53: [
            "add jump-to-offset, byte selection hashing, and exported range citation packages",
            "validate offsets against full-source hashes and source parser context",
        ],
        54: [
            "add large-table pagination, WHERE builder, WAL/journal replay, and deleted-row validation",
            "validate database previews against known-answer SQLite corpora",
        ],
        55: [
            "add native PST/OST/MSG object decoding, deleted item recovery, attachment extraction, and mailbox corpus validation",
            "verify conversation threading and message-id graph reconstruction before reporting",
        ],
        56: [
            "validate virtualized gallery review, persistent tags, ML similarity, and sensitive/deepfake classifier behavior",
            "attach source hash and reviewer selection evidence before report export",
        ],
        57: [
            "validate safe playback, ASR execution, waveform/thumb generation, and transcript alignment corpus",
            "attach reviewed transcript cue citations before report use",
        ],
    }
    return {
        "profile_version": "viewer-workflow-reportability-decision-v1",
        "commercial_gap_ids": [gap_id],
        "component": component,
        "decision": decisions.get(item_number, "do-not-report-viewer-output-as-commercial-complete"),
        "allowed_use": allowed_uses.get(item_number, "bounded-viewer-triage-pivot"),
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "control_snapshot": dict(controls),
        "ready_for_court_report": False,
        "required_before_report": required.get(item_number, ["attach source hash, parser validation, reviewer decision, and export citation evidence"]),
    }


def source_viewer_sandbox(source_path: Path, *, suffix: str, mime_type: str, max_chars: int) -> dict[str, object]:
    active_content = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta"} or mime_type in {
        "text/html",
        "image/svg+xml",
        "application/javascript",
    }
    policy_profile = preview_sandbox_policy_profile(
        source_path=source_path,
        suffix=suffix,
        mime_type=mime_type,
        max_chars=max_chars,
        active_content_blocked=active_content,
    )
    source_manifest = source_preview_sandbox_manifest(policy_profile=policy_profile)
    validation_plan = build_preview_sandbox_report_grade_validation_plan(
        policy_profile=policy_profile,
        source_manifest=source_manifest,
        scope="source-preview",
    )
    return {
        "mode": "read-only-bounded-preview",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "executes_content": False,
        "active_content_blocked": active_content,
        "preview_sandbox_policy_profile": policy_profile,
        "source_preview_sandbox_manifest": source_manifest,
        "source_preview_sandbox_manifest_hash": source_manifest["manifest_hash"],
        "preview_sandbox_report_grade_validation_plan": validation_plan,
        "preview_sandbox_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
        "path_redaction": "display-basename-in-summary-use-full-path-only-for-authorized-source-actions",
        "max_inline_text_chars": max_chars,
        "max_structured_preview_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
        "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
        "external_network_access": False,
        "notes": [
            "Preview routes never execute scripts, macros, HTML, SVG, or embedded active content.",
            "Use source metadata/hash actions for verification before report inclusion.",
        ],
        "preview_sandbox_assessment": source_viewer_component_assessment(
            VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"],
            "preview-sandboxing",
            [
                "preview-is-application-level-bounded-rendering-not-a-separate-os-sandbox",
                "malicious-codecs-and-office-macros-require-external-sandboxed-tooling-before-opening-originals",
                PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            ],
        ),
        "trusted_preview_sandbox_diff": {
            "status": "missing",
            "blocker_id": PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(PREVIEW_SANDBOX_TRUSTED_TOOLS),
        },
        "core_accuracy_gates": preview_sandbox_core_accuracy_gates(
            source_path=source_path,
            active_content_blocked=active_content,
            max_chars=max_chars,
            policy_profile=policy_profile,
            validation_plan=validation_plan,
        ),
    }


def preview_sandbox_policy_profile(
    *,
    source_path: Path,
    suffix: str,
    mime_type: str,
    max_chars: int,
    active_content_blocked: bool,
) -> dict[str, object]:
    dangerous_extension = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta", ".docm", ".xlsm", ".pptm"}
    return {
        "profile_version": "preview-sandbox-policy-profile-v1",
        "source_name": source_path.name,
        "source_path_sha256": hashlib.sha256(str(source_path).encode("utf-8", errors="replace")).hexdigest(),
        "suffix": suffix,
        "mime_type": mime_type,
        "dangerous_extension_detected": dangerous_extension,
        "active_content_blocked": active_content_blocked,
        "executes_content": False,
        "external_network_access": False,
        "renderer_strategy": "escaped-bounded-data-rendering",
        "original_file_opening": "download-only-user-controlled-action",
        "max_inline_text_chars": max_chars,
        "max_structured_preview_bytes": STRUCTURED_PREVIEW_MAX_BYTES,
        "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
        "os_sandbox_enabled": False,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": False,
    }


def source_preview_sandbox_manifest(*, policy_profile: Mapping[str, object]) -> dict[str, object]:
    policy = dict(policy_profile)
    row_core = {
        "source_name": str(policy.get("source_name") or ""),
        "source_path_sha256": str(policy.get("source_path_sha256") or ""),
        "suffix": str(policy.get("suffix") or ""),
        "mime_type": str(policy.get("mime_type") or ""),
        "dangerous_extension_detected": bool(policy.get("dangerous_extension_detected")),
        "active_content_blocked": bool(policy.get("active_content_blocked")),
        "executes_content": bool(policy.get("executes_content")),
        "external_network_access": bool(policy.get("external_network_access")),
        "renderer_strategy": str(policy.get("renderer_strategy") or ""),
        "original_file_opening": str(policy.get("original_file_opening") or ""),
        "os_sandbox_enabled": bool(policy.get("os_sandbox_enabled")),
    }
    row_hash = hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile_version": "source-preview-sandbox-manifest-v1",
        "item_number": 73,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"],
        "policy_profile_hash": hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest(),
        "source_policy_row": {**row_core, "row_hash": row_hash},
        "row_head_hash": hashlib.sha256(row_hash.encode("utf-8")).hexdigest(),
        "active_content_blocking_required": bool(policy.get("dangerous_extension_detected"))
        or bool(policy.get("active_content_blocked")),
        "no_exec_no_network_contract": {
            "executes_content": False,
            "external_network_access": False,
            "renderer_strategy": "escaped-bounded-data-rendering",
            "original_file_opening": "download-only-user-controlled-action",
        },
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": False,
        "blockers": [
            PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
            "browser-renderer-exploit-corpus-not-attached",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_preview_sandbox_report_grade_validation_plan(
    *,
    policy_profile: Mapping[str, object],
    source_manifest: Mapping[str, object],
    scope: str,
) -> dict[str, object]:
    policy = dict(policy_profile)
    manifest_hash = str(source_manifest.get("manifest_hash") or "")
    row_head_hash = str(source_manifest.get("row_head_hash") or "")
    policy_profile_hash = str(source_manifest.get("policy_profile_hash") or "")
    active_content_blocking_required = bool(source_manifest.get("active_content_blocking_required"))
    no_exec_contract = source_manifest.get("no_exec_no_network_contract")
    no_exec_contract_hash = hashlib.sha256(
        json.dumps(no_exec_contract if isinstance(no_exec_contract, Mapping) else {}, sort_keys=True).encode("utf-8")
    ).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "policy-profile",
            "status": "ready",
            "evidence_ref": "policy_profile_hash",
            "evidence_hash": policy_profile_hash,
            "description": "Preview policy profile records source path hash, type, caps, renderer strategy, and no-exec state.",
        },
        {
            "slot_id": "source-policy-row-hash",
            "status": "ready",
            "evidence_ref": "source_preview_sandbox_manifest.row_head_hash",
            "evidence_hash": row_head_hash,
            "description": "Source preview policy row is hashed for source-level reviewer replay.",
        },
        {
            "slot_id": "source-preview-manifest",
            "status": "ready",
            "evidence_ref": "source_preview_sandbox_manifest_hash",
            "evidence_hash": manifest_hash,
            "description": "Source preview sandbox manifest is attached to the viewer payload.",
        },
        {
            "slot_id": "no-exec-no-network-contract",
            "status": "ready",
            "evidence_ref": "no_exec_contract_hash",
            "evidence_hash": no_exec_contract_hash,
            "description": "Viewer metadata preserves no active execution and no external network access.",
        },
        {
            "slot_id": "active-content-blocking",
            "status": "ready",
            "evidence_ref": "active_content_blocking_required",
            "evidence_hash": hashlib.sha256(str(active_content_blocking_required).encode("ascii")).hexdigest(),
            "description": "Dangerous extensions and active content are flagged for blocked escaped rendering.",
        },
        {
            "slot_id": "bounded-render-caps",
            "status": "ready",
            "evidence_ref": "max_preview_caps",
            "evidence_hash": hashlib.sha256(
                json.dumps(
                    {
                        "max_inline_text_chars": int(policy.get("max_inline_text_chars") or 0),
                        "max_structured_preview_bytes": int(policy.get("max_structured_preview_bytes") or 0),
                        "max_hex_preview_bytes": int(policy.get("max_hex_preview_bytes") or 0),
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "description": "Inline text, structured, and hex preview caps are preserved.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "os-level-renderer-sandbox",
            "status": "blocked",
            "blocker": "os-level-renderer-sandbox-required",
            "required_evidence": "platform sandbox proof for HTML/SVG/Office/media renderers and risky codecs",
        },
        {
            "slot_id": "trusted-no-exec-manifest",
            "status": "blocked",
            "blocker": PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER,
            "required_evidence": "trusted no-exec/no-network manifest diff for source preview payloads",
        },
        {
            "slot_id": "browser-renderer-exploit-corpus",
            "status": "blocked",
            "blocker": "browser-renderer-exploit-corpus-required",
            "required_evidence": "browser/renderer exploit corpus showing no script execution or outbound network calls",
        },
        {
            "slot_id": "malicious-active-content-corpus",
            "status": "blocked",
            "blocker": "malicious-active-content-corpus-required",
            "required_evidence": "known-answer HTML/SVG/JS/Office active-content corpus with expected blocked outcomes",
        },
        {
            "slot_id": "risky-codec-macro-external-sandbox",
            "status": "blocked",
            "blocker": "risky-codec-macro-external-sandbox-required",
            "required_evidence": "external sandbox workflow for risky codecs, macros, embedded scripts, and unknown binaries",
        },
        {
            "slot_id": "browser-e2e-preview-sandbox",
            "status": "blocked",
            "blocker": "browser-e2e-preview-sandbox-required",
            "required_evidence": "browser E2E run proving preview pages do not execute active content or contact networks",
        },
    ]
    plan_core = {
        "profile_version": PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 73,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "scope": scope,
        "source_name": str(policy.get("source_name") or ""),
        "source_path_sha256": str(policy.get("source_path_sha256") or ""),
        "source_preview_sandbox_manifest_hash": manifest_hash,
        "policy_profile_hash": policy_profile_hash,
        "row_head_hash": row_head_hash,
        "no_exec_contract_hash": no_exec_contract_hash,
        "active_content_blocking_required": active_content_blocking_required,
        "read_only_preview": True,
        "executes_content": False,
        "external_network_access": False,
        "renderer_strategy": str(policy.get("renderer_strategy") or ""),
        "os_sandbox_enabled": bool(policy.get("os_sandbox_enabled")),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as bounded source preview evidence only until OS renderer sandbox and trusted no-exec corpus validation are attached.",
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_sha256": validation_plan_sha256,
        "validation_plan_hash": validation_plan_sha256,
    }


def build_preview_sandbox_trusted_diff(
    rapid_sandbox: Mapping[str, object],
    trusted_sandbox: Mapping[str, object],
    *,
    trusted_tool: str = "no-exec-preview-manifest",
) -> dict[str, object]:
    rapid = preview_sandbox_diff_value(rapid_sandbox)
    trusted = preview_sandbox_diff_value(trusted_sandbox)
    mismatched = [
        {"field": key, "rapid": rapid.get(key), "trusted": trusted.get(key)}
        for key in sorted(set(rapid).union(trusted))
        if rapid.get(key) != trusted.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "preview-sandbox-trusted-no-exec-diff-v1",
        "item_number": 73,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["preview_sandbox"]],
        "commercial_claim_allowed": status == "pass",
    }


def preview_sandbox_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    policy = item.get("preview_sandbox_policy_profile")
    policy_profile = policy if isinstance(policy, Mapping) else {}
    return {
        "mode": str(item.get("mode") or ""),
        "executes_content": bool(item.get("executes_content")),
        "external_network_access": bool(item.get("external_network_access")),
        "active_content_blocked": bool(item.get("active_content_blocked")),
        "max_inline_text_chars": int(item.get("max_inline_text_chars") or 0),
        "policy_profile_version": str(policy_profile.get("profile_version") or ""),
        "renderer_strategy": str(policy_profile.get("renderer_strategy") or ""),
        "os_sandbox_enabled": bool(policy_profile.get("os_sandbox_enabled")),
    }


def source_viewer_limitations(source_path: Path, *, suffix: str, mime_type: str, max_chars: int) -> list[str]:
    limitations = [
        "Preview is read-only and may be capped to keep large cases responsive.",
        "Use hashes and source download before relying on a preview in a final report.",
    ]
    if mime_type.startswith("image/"):
        limitations.append("Image text requires OCR or OCR sidecar review; the file viewer does not OCR images inline.")
    if is_sqlite_candidate(source_path, suffix):
        limitations.append("SQLite previews show bounded tables/rows; use file search or a dedicated database tool for full table review.")
    if suffix in {".json", ".jsonl", ".ndjson", ".xml"} and source_path.stat().st_size > STRUCTURED_PREVIEW_MAX_BYTES:
        limitations.append("Structured parsing is skipped for very large JSON/XML files; use current-file search or external tooling.")
    if suffix in SUPPORTED_DOC_EXTS and source_path.stat().st_size > DOCUMENT_PREVIEW_MAX_BYTES:
        limitations.append("Document text extraction is bounded for preview; use source search resume or an external parser for full-document validation.")
    if suffix in {".eml", ".mbox"} and source_path.stat().st_size > EMAIL_PREVIEW_MAX_BYTES:
        limitations.append("Email preview is bounded; only the first parse window is shown until mailbox-specific pagination is implemented.")
    if source_path.stat().st_size > max_chars:
        limitations.append(f"Inline text snippets are capped near {max_chars} characters.")
    return limitations


def build_viewer_trusted_diff_result(
    *,
    profile_version: str,
    comparison_id: str,
    rapid_index: Mapping[str, Mapping[str, object]],
    trusted_index: Mapping[str, Mapping[str, object]],
    trusted_tool: str,
    accepted_tools: set[str],
    blocker_id: str,
    compare_fields: Sequence[str],
) -> dict[str, object]:
    rapid = {key: value for key, value in rapid_index.items() if key}
    trusted = {key: value for key, value in trusted_index.items() if key}
    missing_in_trusted = sorted(key for key in rapid if key not in trusted)
    unexpected_in_trusted = sorted(key for key in trusted if key not in rapid)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid) & set(trusted)):
        for field in compare_fields:
            left = rapid[key].get(field)
            right = trusted[key].get(field)
            if left != right:
                mismatches.append({"row_key": key, "field": field, "rapid": left, "trusted": right})
    tool_accepted = trusted_tool.strip().lower() in accepted_tools
    status = "pass" if tool_accepted and rapid and trusted and not missing_in_trusted and not unexpected_in_trusted and not mismatches else "fail"
    return {
        "profile_version": profile_version,
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else blocker_id,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(accepted_tools),
        "rapid_row_count": len(rapid),
        "trusted_row_count": len(trusted),
        "matched_count": len(set(rapid) & set(trusted)),
        "missing_in_trusted_count": len(missing_in_trusted),
        "unexpected_in_trusted_count": len(unexpected_in_trusted),
        "mismatch_count": len(mismatches),
        "mismatched_fields": mismatches[:50],
        "missing_in_trusted": missing_in_trusted[:50],
        "unexpected_in_trusted": unexpected_in_trusted[:50],
        "commercial_grade_evidence": status == "pass",
    }


def structured_viewer_metadata(source_format: str, strategy: str, status: str) -> dict[str, object]:
    return {
        "source_format": source_format,
        "strategy": strategy,
        "preview_status": status,
        "parser": f"rapidtriage.source-viewer.{source_format}",
        "parser_version": SOURCE_VIEWER_VERSION,
    }


def source_viewer_component_assessment(gap_id: str, component: str, blockers: list[str]) -> dict[str, object]:
    return {
        "component": component,
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [gap_id],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Verify the preview against the authoritative source file and source hashes before report inclusion.",
            "Use specialized validated tooling for artifact-specific conclusions beyond this bounded viewer.",
        ],
    }
