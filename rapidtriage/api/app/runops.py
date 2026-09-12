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
    DEFAULT_INTERNAL_VALIDATION_PACKAGE,
    DOCUMENT_PREVIEW_MAX_BYTES,
    HEX_PREVIEW_MAX_BYTES,
    IMAGE_GALLERY_DEFAULT_LIMIT,
    MAX_SOURCE_SEARCH_ARCHIVE_TEXT_CHARS,
    RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT,
    RUN_VIEWER_WORKFLOW_REQUIRED_ROUTES,
    RUN_VIEWER_WORKFLOW_VALIDATION_VERSION,
    SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS,
    SOURCE_VIEWER_VERSION,
    SQLITE_SOURCE_SEARCH_ROW_SCAN_LIMIT,
    STAGE10_CAPABILITY_SPECS,
    VIRTUAL_TABLE_ROW_LIMIT,
)
from .helpers import (
    allowed_source_roots,
    default_case_path,
    default_run_validation_package_path,
    default_submission_manifest_path,
    dt_from_epoch,
    get_job,
    is_probably_binary,
    is_sqlite_candidate,
    model_to_dict,
    optional_int_for_api,
    stable_payload_sha256,
)
from .models import (
    CaseReportCreateRequest,
)
from .viewer_core import (
    archived_source_viewer_actions,
    build_run_validation_diff_inventory,
    build_run_validation_limitations,
    build_run_validation_output_hashes,
    build_run_validation_parser_execution,
    build_run_validation_review_status,
    build_run_validation_source_integrity,
    build_run_validation_warning_inventory,
    build_run_viewer_route_coverage,
    build_run_viewer_workflow_accuracy_gates,
    build_workbench_large_result_evidence,
    build_workbench_smoke_contract,
    collect_bounded_viewer_candidate_path_strings,
    commercial_readiness_focus_item,
    commercial_readiness_validation_package_mode,
    commercial_readiness_validation_package_profile,
    run_viewer_candidate_sort_key,
    source_analyst_workbench_profile,
    source_compare_pin_profile,
    source_compare_workflow_metadata,
    source_review_evidence_tray_profile,
    source_review_workflow_metadata,
    source_stage10_capability_matrix,
    source_viewer_actions,
    source_viewer_family,
    source_viewer_family_for_path,
    source_viewer_limitations,
    source_viewer_sandbox,
    source_viewer_specialization_profile,
    stage10_viewer_item_number,
)
from .email import (
    build_email_preview,
    first_email_attachment_count,
)
from .hex import (
    build_hex_preview,
)
from .image import (
    build_image_preview,
)
from .media import (
    build_media_preview,
    collect_media_transcript_sidecars,
)
from .previews import (
    build_json_preview,
    build_json_preview_from_text,
    build_xml_preview,
    write_json_file,
)
from .search import (
    snippet_around,
    source_search_citation,
    source_search_keywords_digest,
    source_search_locator,
    source_search_source_digest,
)
from .sqlite import (
    build_sqlite_preview,
    first_sqlite_table_name,
    search_sqlite_file,
    sqlite_row_review_note_citation,
)


def build_run_viewer_workflow_validation(
    store: RunJobStore,
    run_id: str,
    run_summary: Mapping[str, object],
) -> dict[str, object]:
    """Summarize source-viewer route coverage for one completed run."""
    candidates, candidate_diagnostics = collect_run_viewer_workflow_source_candidates(
        store,
        run_id,
        run_summary,
    )
    source_rows = [
        build_run_viewer_source_validation_row(
            run_id=run_id,
            source_path=source_path,
            allowed_roots=allowed_source_roots(dict(run_summary)),
        )
        for source_path in candidates
    ]
    route_coverage_by_id = build_run_viewer_route_coverage(source_rows)
    item_coverage = build_run_viewer_item_coverage(source_rows, route_coverage_by_id=route_coverage_by_id)
    family_counts: dict[str, int] = {}
    for row in source_rows:
        family = str(row.get("viewer_family") or "unknown")
        family_counts[family] = family_counts.get(family, 0) + 1
    smoke_contract = build_workbench_smoke_contract()
    large_result_evidence = build_workbench_large_result_evidence(record_count=100_000)
    core_accuracy_gates = build_run_viewer_workflow_accuracy_gates(item_coverage)
    payload: dict[str, object] = {
        "command": "viewer-workflow-validation",
        "profile_version": RUN_VIEWER_WORKFLOW_VALIDATION_VERSION,
        "commercial_batch_id": "commercial-uplift-051-060",
        "item_numbers": list(range(51, 61)),
        "run_id": run_id,
        "summary_path": str(run_summary.get("outputs", {}).get("summary") or "")
        if isinstance(run_summary.get("outputs"), Mapping)
        else "",
        "candidate_summary": {
            "total_candidate_count": len(source_rows),
            "candidate_limit": RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT,
            "viewer_family_counts": family_counts,
            "candidate_collection": candidate_diagnostics,
        },
        "source_viewer_rows": source_rows,
        "route_coverage": list(route_coverage_by_id.values()),
        "route_coverage_by_id": route_coverage_by_id,
        "item_coverage": item_coverage,
        "browser_e2e_contract": {
            "profile_version": "viewer-workflow-browser-e2e-contract-v1",
            "workbench_smoke_contract_hash": smoke_contract["manifest_sha256"],
            "required_routes": list(RUN_VIEWER_WORKFLOW_REQUIRED_ROUTES),
            "required_actions": [
                "open result row",
                "open source preview",
                "open specialized viewer route when applicable",
                "save review state",
                "pin compare candidate",
                "export citation or report candidate",
            ],
            "external_browser_run_required": True,
        },
        "large_data_controls": {
            "source_candidate_collection_bounded": True,
            "source_candidate_limit": RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT,
            "inline_preview_bounded": True,
            "specialized_routes_are_cursor_or_range_bounded": True,
            "virtualized_table_row_limit": VIRTUAL_TABLE_ROW_LIMIT,
            "large_result_evidence_hash": large_result_evidence["evidence_manifest_hash"],
            "browser_trace_attached": False,
        },
        "core_accuracy_gates": core_accuracy_gates,
        "reportability_decision": {
            "decision": "viewer-workflow-validation-is-routing-proof-not-commercial-certification",
            "allowed_use": "single-run-review-route-and-source-locator-qc",
            "required_before_report": [
                "open source row and verify locator/hash",
                "save review state for selected evidence",
                "attach viewer-specific manifest for cited rows",
                "run external browser e2e and trusted viewer corpus before commercial-grade claim",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-viewer-route-run-required",
            "trusted-viewer-corpus-diff-required",
            "persistent-review-server-and-conflict-tests-required",
            "large-file-real-browser-performance-trace-required",
        ],
    }
    payload["manifest_hash"] = stable_payload_sha256(payload)
    return payload


def collect_run_viewer_workflow_source_candidates(
    store: RunJobStore,
    run_id: str,
    run_summary: Mapping[str, object],
) -> tuple[list[Path], dict[str, object]]:
    allowed_roots = allowed_source_roots(dict(run_summary))
    raw_paths: list[str] = []
    load_errors: list[str] = []
    try:
        files_payload = store.read_output(run_id, "files")
    except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError) as exc:
        files_payload = {}
        load_errors.append(f"files:{exc.__class__.__name__}")
    candidates = files_payload.get("candidates") if isinstance(files_payload, Mapping) else None
    if isinstance(candidates, Sequence) and not isinstance(candidates, (str, bytes)):
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            raw_path = str(candidate.get("path") or "")
            if raw_path:
                raw_paths.append(raw_path)
    docs_payload: Mapping[str, object] = {}
    try:
        docs_payload = store.read_output(run_id, "docs")
    except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError) as exc:
        load_errors.append(f"docs:{exc.__class__.__name__}")
    doc_rows = docs_payload.get("results") if isinstance(docs_payload, Mapping) else None
    if isinstance(doc_rows, Sequence) and not isinstance(doc_rows, (str, bytes)):
        for row in doc_rows:
            if not isinstance(row, Mapping):
                continue
            raw_path = str(row.get("path") or "")
            if raw_path:
                raw_paths.append(raw_path)
    supplemental_paths, supplemental_scan = collect_bounded_viewer_candidate_path_strings(
        allowed_roots,
        existing_raw_paths=raw_paths,
    )
    raw_paths.extend(supplemental_paths)

    deduped: list[Path] = []
    skipped_outside_roots = 0
    missing_files = 0
    for raw_path in raw_paths:
        resolved: Path | None = None
        for candidate in candidate_source_paths(raw_path, allowed_roots):
            if not any(is_relative_to(candidate, root) for root in allowed_roots):
                continue
            if candidate.is_file():
                resolved = candidate
                break
        if resolved is None:
            scoped = [
                candidate
                for candidate in candidate_source_paths(raw_path, allowed_roots)
                if any(is_relative_to(candidate, root) for root in allowed_roots)
            ]
            if scoped:
                missing_files += 1
            else:
                skipped_outside_roots += 1
            continue
        if resolved not in deduped:
            deduped.append(resolved)

    ranked = sorted(deduped, key=run_viewer_candidate_sort_key)
    selected: list[Path] = []
    selected_families: set[str] = set()
    for source_path in ranked:
        family = source_viewer_family_for_path(source_path)
        if family in selected_families:
            continue
        selected.append(source_path)
        selected_families.add(family)
        if len(selected) >= RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT:
            break
    for source_path in ranked:
        if len(selected) >= RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT:
            break
        if source_path not in selected:
            selected.append(source_path)

    diagnostics = {
        "profile_version": "run-viewer-source-candidate-collection-v1",
        "raw_path_count": len(raw_paths),
        "deduped_candidate_count": len(deduped),
        "selected_candidate_count": len(selected),
        "candidate_limit": RUN_VIEWER_WORKFLOW_CANDIDATE_LIMIT,
        "allowed_roots": [str(root) for root in allowed_roots],
        "skipped_outside_allowed_roots": skipped_outside_roots,
        "missing_file_count": missing_files,
        "load_errors": load_errors,
        "supplemental_root_scan": supplemental_scan,
        "bounded": True,
    }
    diagnostics["collection_hash"] = stable_payload_sha256(diagnostics)
    return selected, diagnostics


def build_run_viewer_source_validation_row(
    *,
    run_id: str,
    source_path: Path,
    allowed_roots: Sequence[Path],
) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    viewer_family = source_viewer_family(source_path, suffix=suffix, mime_type=mime_type)
    quoted_path = quote(str(source_path))
    matrix = source_stage10_capability_matrix(
        run_id=run_id,
        source_path=source_path,
        quoted_path=quoted_path,
        viewer_family=viewer_family,
    )
    stat = source_path.stat()
    route_rows = build_run_viewer_route_rows(
        run_id=run_id,
        source_path=source_path,
        viewer_family=viewer_family,
    )
    source_resolution = source_path_resolution_diagnostics(str(source_path), allowed_roots)
    return {
        "source_path": str(source_path),
        "source_name": source_path.name,
        "extension": suffix,
        "mime_type": mime_type,
        "size": stat.st_size,
        "viewer_family": viewer_family,
        "primary_item_number": stage10_viewer_item_number(viewer_family),
        "source_exists": True,
        "source_preview_url": f"/api/runs/{run_id}/source-preview?path={quoted_path}",
        "source_file_url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
        "source_locator_validation": {
            "profile_version": "source-locator-run-validation-v1",
            "status": "resolved-inside-allowed-root"
            if source_resolution["status"] == "matched"
            else "source-resolution-needs-review",
            "path_resolution_status": source_resolution["status"],
            "inside_allowed_root_count": source_resolution["inside_allowed_root_count"],
            "existing_file_count": source_resolution["existing_file_count"],
            "source_locator_hash": stable_payload_sha256(
                {
                    "run_id": run_id,
                    "source_path": str(source_path),
                    "viewer_family": viewer_family,
                    "size": stat.st_size,
                }
            ),
        },
        "stage10_capability_matrix_hash": stable_payload_sha256(matrix),
        "routes": route_rows,
    }


def build_run_viewer_route_rows(
    *,
    run_id: str,
    source_path: Path,
    viewer_family: str,
) -> list[dict[str, object]]:
    quoted_path = quote(str(source_path))
    rows: list[dict[str, object]] = [
        {
            "route_id": "source-preview",
            "item_numbers": [51, 52],
            "url": f"/api/runs/{run_id}/source-preview?path={quoted_path}",
            "sample_ready": True,
            "purpose": "Open the adaptive source viewer and review/compare controls.",
        },
        {
            "route_id": "source-hex-range",
            "item_numbers": [53],
            "url": f"/api/runs/{run_id}/source-hex-range?path={quoted_path}&offset=0&length=256&include_hashes=true",
            "sample_ready": True,
            "purpose": "Export a bounded byte-range citation package.",
        },
    ]
    if viewer_family == "sqlite-table-preview":
        table_name = first_sqlite_table_name(source_path)
        rows.append(
            {
                "route_id": "source-sqlite-table",
                "item_numbers": [54],
                "url": f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={quote(table_name)}&offset=0&limit=100"
                if table_name
                else f"/api/runs/{run_id}/source-sqlite-table?path={quoted_path}&table={{table}}&offset=0&limit=100",
                "sample_ready": bool(table_name),
                "purpose": "Open a read-only paged SQLite table view.",
                "route_parameter_source": "first_table" if table_name else "analyst-selected-table-required",
            }
        )
    if viewer_family == "email-thread-preview":
        attachment_count = first_email_attachment_count(source_path)
        rows.append(
            {
                "route_id": "source-email-attachment",
                "item_numbers": [55],
                "url": f"/api/runs/{run_id}/source-email-attachment?path={quoted_path}&message_index=1&attachment_index=1",
                "sample_ready": attachment_count > 0,
                "purpose": "Open a bounded email attachment proof package when an attachment exists.",
                "attachment_count": attachment_count,
            }
        )
    if viewer_family == "image-gallery-preview":
        rows.extend(
            [
                {
                    "route_id": "source-image-gallery",
                    "item_numbers": [56],
                    "url": f"/api/runs/{run_id}/source-image-gallery?path={quoted_path}&offset=0&limit={IMAGE_GALLERY_DEFAULT_LIMIT}",
                    "sample_ready": True,
                    "purpose": "Open nearby-image review and gallery triage.",
                },
                {
                    "route_id": "source-ocr-queue",
                    "item_numbers": [58],
                    "url": f"/api/runs/{run_id}/source-ocr-queue?path={quoted_path}&max_items={SOURCE_OCR_QUEUE_DEFAULT_MAX_ITEMS}",
                    "sample_ready": True,
                    "purpose": "Open OCR work queue candidates around the selected image.",
                },
                {
                    "route_id": "source-ocr-translation",
                    "item_numbers": [59],
                    "url": f"/api/runs/{run_id}/source-ocr-translation?path={quoted_path}&include_text=true",
                    "sample_ready": True,
                    "purpose": "Open side-by-side OCR and translation review.",
                },
            ]
        )
    if viewer_family == "media-preview":
        sidecar_count = len(collect_media_transcript_sidecars(source_path))
        rows.append(
            {
                "route_id": "source-media-cue",
                "item_numbers": [57],
                "url": f"/api/runs/{run_id}/source-media-cue?path={quoted_path}&sidecar_index=1&cue_index=1&include_source_hashes=true",
                "sample_ready": sidecar_count > 0,
                "purpose": "Open a selected transcript cue citation package.",
                "sidecar_count": sidecar_count,
            }
        )
    for row in rows:
        row["route_hash"] = stable_payload_sha256(
            {
                "route_id": row["route_id"],
                "url": row["url"],
                "source_path": str(source_path),
            }
        )
    return rows


def build_run_viewer_item_coverage(
    source_rows: Sequence[Mapping[str, object]],
    *,
    route_coverage_by_id: Mapping[str, object],
) -> list[dict[str, object]]:
    route_to_items = {
        "source-preview": [51, 52],
        "source-hex-range": [53],
        "source-sqlite-table": [54],
        "source-email-attachment": [55],
        "source-image-gallery": [56],
        "source-media-cue": [57],
        "source-ocr-queue": [58],
        "source-ocr-translation": [59],
    }
    item_counts = {item: 0 for item in range(51, 61)}
    item_sample_ready = {item: 0 for item in range(51, 61)}
    for route_id, items in route_to_items.items():
        coverage = route_coverage_by_id.get(route_id)
        if not isinstance(coverage, Mapping):
            continue
        for item in items:
            item_counts[item] += int(coverage.get("candidate_count") or 0)
            item_sample_ready[item] += int(coverage.get("sample_ready_count") or 0)
    duplicate_group_count = 0
    for row in source_rows:
        if source_viewer_family_for_path(Path(str(row.get("source_path") or ""))) in {
            "document-text-preview",
            "text-or-hex-preview",
            "json-structured-preview",
            "xml-structured-preview",
        }:
            duplicate_group_count += 1
    item_counts[60] = duplicate_group_count
    item_sample_ready[60] = duplicate_group_count
    labels = {int(spec["item_number"]): str(spec["label"]) for spec in STAGE10_CAPABILITY_SPECS}
    rows: list[dict[str, object]] = []
    for item in range(51, 61):
        row = {
            "item_number": item,
            "gap_id": f"#{item}",
            "label": labels[item],
            "implemented": True,
            "candidate_count": item_counts[item],
            "sample_ready_count": item_sample_ready[item],
            "validated_in_this_run": item_sample_ready[item] > 0,
            "commercial_grade_ready": False,
        }
        row["coverage_hash"] = stable_payload_sha256(row)
        rows.append(row)
    return rows


def build_run_output_preview(*, run_id: str, output_name: str, output_path: Path) -> dict[str, object]:
    payload = build_source_preview(run_id, output_path)
    preview_limit = int(payload.get("viewer_sandbox", {}).get("max_inline_text_chars") or 20000)
    payload.update(
        {
            "command": "run-output-preview",
            "output_name": output_name,
            "download_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
            "metadata_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/preview",
            "search_url": "",
            "viewer_actions": [
                {
                    "id": "download-output",
                    "label": "Download output",
                    "url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
                    "purpose": "Open the run output file that backs this workflow stage.",
                    "heavy": False,
                },
                {
                    "id": "open-run-summary",
                    "label": "Open run summary",
                    "url": f"/api/runs/{run_id}/summary",
                    "purpose": "Check workflow stage status and output provenance before citing this output.",
                    "heavy": False,
                },
            ],
            "output_preview_profile": {
                "profile_version": "run-output-preview-v1",
                "output_name": output_name,
                "output_path": str(output_path),
                "preview_type": payload.get("preview_type") or "binary",
                "bounded": True,
                "max_inline_text_chars": preview_limit,
                "download_url": f"/api/runs/{run_id}/outputs/{quote(output_name)}/file",
                "reportability_decision": {
                    "decision": "run-output-preview-is-review-aid",
                    "allowed_use": "analyst-output-verification-and-workflow-handoff",
                    "required_before_report": [
                        "verify source row or artifact provenance inside the output",
                        "check workflow stage warning_messages and parser limitations",
                        "cite source evidence rather than this preview when possible",
                    ],
                },
            },
        }
    )
    payload["viewer_limitations"] = [
        "Run output preview is bounded and read-only.",
        "Download or open the full output when the preview is truncated.",
        "Report citations should point to source rows/provenance, not only this preview.",
    ]
    return payload


def build_run_submission_manifest(
    store: RunJobStore,
    run_id: str,
    *,
    include_all: bool,
    max_items: int,
) -> dict[str, object]:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    try:
        return build_submission_manifest(
            case_payload,
            allowed_roots=allowed_source_roots(job.summary),
            include_all=include_all,
            max_items=max_items,
        )
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def build_run_case_report(
    store: RunJobStore,
    run_id: str,
    request: CaseReportCreateRequest,
) -> str:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    case_path = default_case_path(store, run_id)
    if not case_path.is_file():
        raise HTTPException(status_code=404, detail="case review file not found")
    try:
        case_payload = load_case_payload(case_path)
    except CaseBookmarkError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    manifest = build_run_submission_manifest(
        store,
        run_id,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    manifest_path = default_submission_manifest_path(store, run_id)
    write_json_file(manifest_path, manifest)
    write_submission_audit(
        store,
        run_id,
        manifest_path,
        include_all=request.include_all,
        max_items=request.max_items,
    )
    return build_case_report_markdown(
        run_summary=job.summary,
        case_payload=case_payload,
        submission_manifest=manifest,
        metadata=model_to_dict(request),
    )


def build_run_validation_package(store: RunJobStore, run_id: str) -> dict[str, object]:
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")
    summary = job.summary
    output_dir = run_output_dir(summary)
    case_path = default_case_path(store, run_id)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    source_integrity = build_run_validation_source_integrity(summary)
    output_hashes = build_run_validation_output_hashes(summary, output_dir=output_dir)
    review_status = build_run_validation_review_status(case_path)
    warning_inventory = build_run_validation_warning_inventory(summary)
    diff_inventory = build_run_validation_diff_inventory(summary)
    diff_attached = bool(diff_inventory.get("attached"))
    diff_pass_count = int(diff_inventory.get("usn_state_replay_diff_pass_count") or 0)
    trusted_diff_blocker = ""
    if not diff_attached:
        trusted_diff_blocker = "trusted-tool-diffs-not-attached"
    elif diff_pass_count <= 0:
        trusted_diff_blocker = "trusted-tool-diff-pass-not-established"
    passed_validation_check_ids = [
        "run-command-and-request-recorded",
        "source-integrity-or-limitation-recorded",
        "output-hash-manifest-recorded",
        "parser-warning-inventory-recorded",
        "review-status-inventory-recorded",
        "package-manifest-hash-recorded",
    ]
    if diff_attached:
        passed_validation_check_ids.append("trusted-tool-diff-output-attached")
    if diff_pass_count > 0:
        passed_validation_check_ids.append("trusted-tool-diff-pass-recorded")
    failed_validation_check_ids = [
        item
        for item in [
            trusted_diff_blocker,
            "independent-review-not-attached",
            "real-case-validation-transcripts-required",
        ]
        if item
    ]
    commercial_grade_blockers = [
        item
        for item in [
            trusted_diff_blocker,
            "independent-review-not-attached",
            "operator-signed-validation-transcripts-required",
        ]
        if item
    ]
    limitation_inventory = build_run_validation_limitations(
        source_integrity=source_integrity,
        output_hashes=output_hashes,
        warning_inventory=warning_inventory,
        diff_inventory=diff_inventory,
        review_status=review_status,
    )
    package_core: dict[str, object] = {
        "command": "run.validation-package",
        "profile_version": "run-validation-package-v1",
        "immediate_queue_item": 9,
        "run_id": run_id,
        "job": {
            "status": job.status,
            "origin": job.origin,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "retry_of_run_id": job.retry_of_run_id,
            "retry_attempt": job.retry_attempt,
        },
        "request": job.request.to_dict(),
        "run_summary": {
            "mode": summary.get("mode"),
            "root": summary.get("root"),
            "scan_scope_root": summary.get("scan_scope_root"),
            "output_dir": str(output_dir),
            "generated_at": summary.get("generated_at"),
            "summary": summary.get("summary") if isinstance(summary.get("summary"), Mapping) else {},
        },
        "source_integrity": source_integrity,
        "output_hashes": output_hashes,
        "parser_execution": build_run_validation_parser_execution(job.to_dict(include_summary=False), summary),
        "warning_inventory": warning_inventory,
        "diff_inventory": diff_inventory,
        "review_status": review_status,
        "limitation_inventory": limitation_inventory,
        "implemented_controls": {
            "command_inventory": True,
            "source_hashes_or_limitation": True,
            "output_hash_manifest": bool(output_hashes["items"]) or bool(output_hashes["missing"]),
            "parser_warning_inventory": True,
            "reviewer_status_inventory": True,
            "diff_result_inventory": True,
            "trusted_diff_attached": diff_attached,
            "trusted_diff_pass_recorded": diff_pass_count > 0,
            "package_manifest_hash": True,
            "independent_review_attached": False,
        },
        "functional_priority_profile": {
            "queue_item_number": 9,
            "batch_id": "functional-priority-001-010",
            "component": "run-validation-package",
            "status": "implemented-usable-external-validation-required",
            "passed_validation_check_ids": passed_validation_check_ids,
            "failed_validation_check_ids": failed_validation_check_ids,
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": commercial_grade_blockers,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(package_core, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        **package_core,
        "generated_at": generated_at,
        "output_path": str(default_run_validation_package_path(store, run_id)),
        "package_manifest_hash": manifest_hash,
    }


def build_commercial_readiness_api_payload(
    report: Mapping[str, object],
    *,
    next_gate: str,
    limit: int,
    validation_package_path: Path | None = None,
    include_internal_validation: bool = False,
) -> dict[str, object]:
    maturity_summary = report.get("maturity_gate_summary") if isinstance(report.get("maturity_gate_summary"), Mapping) else {}
    gate_counts = maturity_summary.get("gate_counts") if isinstance(maturity_summary.get("gate_counts"), Mapping) else {}
    blocker_separation = (
        report.get("blocker_separation_profile")
        if isinstance(report.get("blocker_separation_profile"), Mapping)
        else {}
    )
    blocker_summary = (
        blocker_separation.get("summary")
        if isinstance(blocker_separation.get("summary"), Mapping)
        else {}
    )
    items = [item for item in report.get("all_items", []) if isinstance(item, Mapping)]
    normalized_next_gate = next_gate.strip()
    if normalized_next_gate.lower() == "priority":
        focused_source = [item for item in report.get("priority_work_plan", []) if isinstance(item, Mapping)]
    else:
        focused_source = [
            item
            for item in items
            if str(item.get("next_required_gate") or "") == normalized_next_gate
        ]
    focused_items = [
        commercial_readiness_focus_item(item)
        for item in focused_source[: max(limit, 0)]
    ]
    return {
        "command": "commercial-readiness",
        "api_profile": {
            "profile_version": "commercial-readiness-gui-gate-v1",
            "gui_binding": "commercial-readiness-gate",
            "claim_policy": "do-not-claim-commercial-parity-when-commercial_claim_allowed-is-false",
            "default_next_gate": "commercial_grade",
            "validation_package_mode": commercial_readiness_validation_package_mode(
                validation_package_path,
                include_internal_validation=include_internal_validation,
            ),
            "internal_validation_package_available": DEFAULT_INTERNAL_VALIDATION_PACKAGE.is_file(),
        },
        "generated_at": report.get("generated_at"),
        "status": report.get("status"),
        "release_claim": report.get("release_claim"),
        "commercial_claim_allowed": bool(report.get("commercial_claim_allowed")),
        "readiness_score": int(report.get("readiness_score") or 0),
        "item_count": int(report.get("item_count") or 0),
        "commercial_ready_count": int(report.get("commercial_ready_count") or 0),
        "non_commercial_count": int(report.get("non_commercial_count") or 0),
        "maturity_gate_summary": maturity_summary,
        "gate_counts": gate_counts,
        "validation_evidence_summary": report.get("validation_evidence_summary", {}),
        "mac_first_evidence_summary": report.get("mac_first_evidence_summary", {}),
        "validation_package": commercial_readiness_validation_package_profile(validation_package_path),
        "blocker_separation_summary": blocker_summary,
        "focused_next_gate": normalized_next_gate,
        "focused_limit": limit,
        "focused_items": focused_items,
        "operator_guidance": list(report.get("operator_guidance", []))[:6]
        if isinstance(report.get("operator_guidance"), list)
        else [],
        "workbench_actions": [
            {
                "id": "open-validation-package",
                "label": "Open run validation package",
                "required_before_claim": True,
            },
            {
                "id": "attach-trusted-diff",
                "label": "Attach trusted-tool diff / known-answer evidence",
                "required_before_claim": True,
            },
            {
                "id": "rerun-commercial-readiness",
                "label": "Rerun commercial-readiness after evidence is attached",
                "required_before_claim": True,
                "command": "rapidtriage commercial-readiness --validation-package <package.json> --json",
            },
        ],
    }


def write_submission_audit(
    store: RunJobStore,
    run_id: str,
    manifest_path: Path,
    *,
    include_all: bool,
    max_items: int,
) -> None:
    case_path = default_case_path(store, run_id)
    write_audit_record(
        audit_path_for(manifest_path),
        command="submission-manifest",
        options={"include_all": include_all, "max_items": max_items},
        input_files=[("case-json", case_path)],
        output_files=[("submission-manifest", manifest_path)],
    )


def write_run_validation_package_audit(store: RunJobStore, run_id: str, package_path: Path) -> None:
    job = get_job(store, run_id)
    input_files = [("run-summary", Path(str(job.summary["outputs"]["summary"])))] if job.summary else []
    case_path = default_case_path(store, run_id)
    if case_path.is_file():
        input_files.append(("case-json", case_path))
    write_audit_record(
        audit_path_for(package_path),
        command="run-validation-package",
        options={"run_id": run_id},
        input_files=input_files,
        output_files=[("run-validation-package", package_path)],
    )


def write_case_report_audit(
    store: RunJobStore,
    run_id: str,
    report_path: Path,
    request: CaseReportCreateRequest,
) -> None:
    case_path = default_case_path(store, run_id)
    manifest_path = default_submission_manifest_path(store, run_id)
    exports = case_report_export_paths(report_path)
    write_audit_record(
        audit_path_for(report_path),
        command="case-report",
        options=model_to_dict(request),
        input_files=[("case-json", case_path), ("submission-manifest", manifest_path)],
        output_files=[
            ("case-report", exports["md"]),
            ("case-report-html", exports["html"]),
            ("case-report-docx", exports["docx"]),
            ("case-report-pdf", exports["pdf"]),
            ("case-report-export-manifest", exports["manifest"]),
        ],
    )


def build_archived_source_api_preview(run_id: str, archive_path: Path, entry_name: str, *, max_chars: int = 20000) -> dict[str, object]:
    try:
        preview, archive_entry = build_archived_source_read_preview(
            archive_path,
            entry_name=entry_name,
            max_chars=max_chars,
            hex_bytes=HEX_PREVIEW_MAX_BYTES,
        )
    except SourceReadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    stat = archive_path.stat()
    displayed_entry = str(archive_entry["archive_entry_name"])
    display_path = f"{archive_path}::{displayed_entry}"
    entry_path = Path(displayed_entry)
    suffix = entry_path.suffix.lower()
    mime_type = mimetypes.guess_type(entry_path.name)[0] or "application/octet-stream"
    quoted_archive_path = quote(str(archive_path))
    quoted_display_path = quote(display_path)
    source_locator = build_source_locator(preview)
    viewer_limitations = source_viewer_limitations(archive_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars)
    viewer_limitations.extend(
        [
            "ZIP entry preview is read in-memory without extraction and is capped to one bounded archive member.",
            "Archive completeness, original container provenance, nested archives, and encrypted entries require separate validation.",
        ]
    )
    payload: dict[str, object] = {
        "path": display_path,
        "container_path": str(archive_path),
        "name": entry_path.name,
        "extension": suffix,
        "size": int(archive_entry["archive_entry_size"]),
        "container_size": stat.st_size,
        "modified_at": archive_entry.get("archive_entry_modified_at") or "",
        "container_modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
        "mime_type": mime_type,
        "download_url": f"/api/runs/{run_id}/source-file?path={quoted_archive_path}",
        "metadata_url": f"/api/runs/{run_id}/source-metadata?path={quoted_archive_path}&hash=true",
        "search_url": f"/api/runs/{run_id}/source-search?path={quoted_display_path}",
        "viewer_actions": archived_source_viewer_actions(run_id, archive_path, display_path),
        "viewer_limitations": viewer_limitations,
        "viewer_sandbox": source_viewer_sandbox(archive_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars),
        "source_viewer_specialization_profile": source_viewer_specialization_profile(
            run_id=run_id,
            source_path=archive_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "review_evidence_tray_profile": source_review_evidence_tray_profile(run_id=run_id, source_path=archive_path),
        "review_workflow": source_review_workflow_metadata(),
        "compare_workflow": source_compare_workflow_metadata(),
        "compare_pin_profile": source_compare_pin_profile(run_id=run_id, source_path=archive_path),
        "analyst_workbench_profile": source_analyst_workbench_profile(
            run_id=run_id,
            source_path=archive_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "preview_type": preview.get("preview_type", "binary"),
        "text": preview.get("text", ""),
        "hex": preview.get("hex", {}),
        "truncated": bool(preview.get("truncated", False)),
        "message": preview.get("message", "ZIP entry preview is available."),
        "archive_entry": archive_entry,
        "zip_entry": preview,
        "source_locator": source_locator,
        "viewer_metadata": {
            "source_format": suffix.lstrip(".") or "archive-entry",
            "strategy": preview.get("strategy", "bounded-zip-entry"),
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.zip-entry",
            "parser_version": SOURCE_VIEWER_VERSION,
            "container_type": "zip",
            "container_path": str(archive_path),
            "archive_entry_name": displayed_entry,
            "archive_entry_crc32": archive_entry.get("archive_entry_crc32"),
            "archive_entry_size": archive_entry.get("archive_entry_size"),
            "source_preview_path": display_path,
            "source_preview_url": f"/api/runs/{run_id}/source-preview?path={quoted_display_path}",
        },
    }
    if suffix in {".json", ".jsonl", ".ndjson"} and preview.get("preview_type") == "text":
        payload.update(build_json_preview_from_text(str(preview.get("text") or ""), suffix))
        payload["viewer_metadata"].update(
            {
                "parser": "rapidtriage.source-viewer.zip-entry-json",
                "container_type": "zip",
                "container_path": str(archive_path),
                "archive_entry_name": displayed_entry,
                "archive_entry_crc32": archive_entry.get("archive_entry_crc32"),
                "archive_entry_size": archive_entry.get("archive_entry_size"),
                "source_preview_path": display_path,
                "source_preview_url": f"/api/runs/{run_id}/source-preview?path={quoted_display_path}",
            }
        )
    return payload


def build_source_preview(run_id: str, source_path: Path, *, max_chars: int = 20000) -> dict[str, object]:
    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    quoted_path = quote(str(source_path))
    payload: dict[str, object] = {
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "modified_at": source_path.stat().st_mtime,
        "mime_type": mime_type,
        "download_url": f"/api/runs/{run_id}/source-file?path={quoted_path}",
        "metadata_url": f"/api/runs/{run_id}/source-metadata?path={quoted_path}",
        "search_url": f"/api/runs/{run_id}/source-search?path={quoted_path}",
        "viewer_actions": source_viewer_actions(run_id, source_path),
        "viewer_limitations": source_viewer_limitations(source_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars),
        "viewer_sandbox": source_viewer_sandbox(source_path, suffix=suffix, mime_type=mime_type, max_chars=max_chars),
        "source_viewer_specialization_profile": source_viewer_specialization_profile(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "review_evidence_tray_profile": source_review_evidence_tray_profile(run_id=run_id, source_path=source_path),
        "review_workflow": source_review_workflow_metadata(),
        "compare_workflow": source_compare_workflow_metadata(),
        "compare_pin_profile": source_compare_pin_profile(run_id=run_id, source_path=source_path),
        "analyst_workbench_profile": source_analyst_workbench_profile(
            run_id=run_id,
            source_path=source_path,
            suffix=suffix,
            mime_type=mime_type,
            max_chars=max_chars,
        ),
        "preview_type": "binary",
        "text": "",
        "truncated": False,
        "message": "No inline preview is available for this file type.",
        "viewer_metadata": {
            "source_format": suffix.lstrip(".") or "unknown",
            "strategy": "binary-fallback",
            "preview_status": "not-available",
            "parser": "rapidtriage.source-viewer",
            "parser_version": SOURCE_VIEWER_VERSION,
        },
    }
    if mime_type.startswith("image/"):
        payload.update(build_image_preview(source_path, image_url=str(payload["download_url"]), run_id=run_id))
        return payload
    if is_sqlite_candidate(source_path, suffix):
        payload.update(build_sqlite_preview(source_path, run_id=run_id))
        return payload
    if suffix in {".json", ".jsonl", ".ndjson"}:
        payload.update(build_json_preview(source_path, suffix))
        return payload
    if suffix == ".xml":
        payload.update(build_xml_preview(source_path))
        return payload
    if suffix in {".eml", ".mbox"}:
        payload.update(build_email_preview(source_path, suffix, run_id=run_id))
        return payload
    if mime_type.startswith(("audio/", "video/")):
        payload.update(build_media_preview(source_path, mime_type=mime_type, run_id=run_id))
        return payload

    text = ""
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(
                source_path,
                suffix.lstrip("."),
                max_input_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
                max_archive_member_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
                max_archive_total_bytes=DOCUMENT_PREVIEW_MAX_BYTES,
            )
        except Exception as exc:
            payload["message"] = f"Text extraction failed: {exc}"
            return payload
    elif stat.st_size <= 2_000_000 and not is_probably_binary(source_path):
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except UnicodeError as exc:
            payload["message"] = f"Text decoding failed: {exc}"
            return payload

    if text:
        payload["preview_type"] = "text"
        payload["text"] = text[:max_chars]
        payload["truncated"] = len(text) > max_chars
        payload["message"] = "Text preview is available."
        payload["viewer_metadata"] = {
            "source_format": suffix.lstrip(".") or "text",
            "strategy": "bounded-text",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.text",
            "parser_version": SOURCE_VIEWER_VERSION,
            "max_chars": max_chars,
        }
        return payload
    payload.update(build_hex_preview(source_path, run_id=run_id))
    return payload


def attach_search_result_source_actions(payload: MutableMapping[str, object], run_id: str) -> None:
    matches = payload.get("matches")
    if not isinstance(matches, list):
        return
    actionable = 0
    for index, match in enumerate(matches):
        if not isinstance(match, MutableMapping):
            continue
        action_profile = build_search_result_source_action_profile(run_id, match, index=index)
        match["source_viewer_action_profile"] = action_profile
        if action_profile.get("viewer_supported"):
            actionable += 1
    payload["search_result_source_action_profile"] = {
        "profile_version": "search-result-source-viewer-actions-summary-v1",
        "qc_prep_item": 6,
        "match_count": len(matches),
        "actionable_viewer_count": actionable,
        "viewer_action_contract": "search-result-source-viewer-actions-v1",
        "required_gui_selector": "[data-testid='search-result-source-actions']",
        "required_before_report": [
            "open source viewer",
            "verify source locator and source hash",
            "save review decision before include-in-report",
        ],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-e2e-search-result-viewer-action-evidence-required",
            "trusted-source-locator-diff-required",
        ],
    }


def build_search_result_source_action_profile(
    run_id: str,
    match: Mapping[str, object],
    *,
    index: int,
) -> dict[str, object]:
    path = str(match.get("path") or "")
    pointer = str(match.get("pointer") or "")
    source = str(match.get("source") or "")
    quoted_path = quote(path)
    viewer_supported = bool(path)
    matched_keywords = [
        str(item)
        for item in (match.get("matched_keywords") or [])
        if str(item).strip()
    ]
    keyword_query = "".join(f"&keyword={quote(item)}" for item in matched_keywords)
    review_source = review_source_for_search_match(match)
    review_context = {
        "source": review_source,
        "pointer": pointer,
        "title": str(match.get("title") or (Path(path).name if path else "search hit")),
        "path": path,
        "note": str(match.get("preview") or ""),
        "tags": [item for item in [source, str(match.get("kind") or "")] if item],
    }
    actions: list[dict[str, object]] = [
        {
            "id": "open-source-viewer",
            "label": "View / review",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-preview?path={quoted_path}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "data-view-source-path",
            "must_precede_report": True,
        },
        {
            "id": "open-source-file",
            "label": "Open source",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-file?path={quoted_path}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "href",
            "must_precede_report": False,
        },
        {
            "id": "search-inside-source",
            "label": "Search inside",
            "method": "GET",
            "url": f"/api/runs/{quote(run_id)}/source-search?path={quoted_path}{keyword_query}" if path else "",
            "enabled": viewer_supported,
            "gui_binding": "viewer-current-file-search",
            "must_precede_report": True,
            "keywords": matched_keywords,
        },
        {
            "id": "pin-compare",
            "label": "Pin compare",
            "method": "UI",
            "url": "",
            "enabled": viewer_supported,
            "gui_binding": "data-compare-item",
            "must_precede_report": False,
        },
        {
            "id": "save-review",
            "label": "Mark",
            "method": "POST",
            "url": f"/api/runs/{quote(run_id)}/bookmarks",
            "enabled": bool(review_source and pointer),
            "gui_binding": "data-bookmark-source",
            "must_precede_report": True,
        },
    ]
    blockers: list[str] = []
    if not path:
        blockers.append("source-path-required-for-viewer-action")
    if not pointer:
        blockers.append("search-result-pointer-required-for-review-action")
    if not review_source:
        blockers.append("bookmark-source-mapping-required")
    return {
        "profile_version": "search-result-source-viewer-actions-v1",
        "qc_prep_item": 6,
        "search_result_index": index,
        "search_result_id": str(match.get("search_result_id") or ""),
        "source": source,
        "kind": str(match.get("kind") or ""),
        "path": path,
        "pointer": pointer,
        "viewer_supported": viewer_supported,
        "review_context": review_context,
        "actions": actions,
        "ready_for_report_workflow": viewer_supported and bool(review_source and pointer),
        "blockers": blockers,
        "report_use_rule": "Search result rows are leads until the source viewer action is opened and review state is saved.",
    }


def review_source_for_search_match(match: Mapping[str, object]) -> str:
    source = str(match.get("source") or "")
    if source == "documents":
        return "docs"
    if source in {"files", "ocr"}:
        return "files"
    if source == "timeline":
        return "timeline"
    if source == "indicators":
        return "indicators"
    if source == "web":
        return "artifacts:browser"
    if source == "artifacts":
        kind = str(match.get("kind") or "").strip()
        return f"artifacts:{kind}" if kind else ""
    return ""


def build_source_metadata(source_path: Path, *, include_hashes: bool) -> dict[str, object]:
    stat = source_path.stat()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    payload: dict[str, object] = {
        "command": "source-metadata",
        "path": str(source_path),
        "name": source_path.name,
        "extension": source_path.suffix.lower(),
        "size": stat.st_size,
        "modified_at": dt_from_epoch(stat.st_mtime),
        "created_at": dt_from_epoch(getattr(stat, "st_birthtime", stat.st_ctime)),
        "mime_type": mime_type,
        "hashes": {},
        "hash_status": "not-requested",
        "hash_cache_assessment": hash_cache_assessment(),
    }
    if include_hashes:
        payload["hashes"] = compute_hashes(source_path)
        payload["hash_status"] = "computed"
        payload["hash_cache_assessment"] = hash_cache_assessment()
    return payload


def build_source_search(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int = 100,
    context: int = 120,
    max_plain_text_bytes: int = 50_000_000,
    sqlite_row_scan_limit: int | None = SQLITE_SOURCE_SEARCH_ROW_SCAN_LIMIT,
    sqlite_resume_token: str | None = None,
    file_resume_token: str | None = None,
) -> dict[str, object]:
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one keyword is required")

    stat = source_path.stat()
    suffix = source_path.suffix.lower()
    mime_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
    matches: list[dict[str, object]] = []
    truncated = False
    search_diagnostics: dict[str, object] = {"max_plain_text_bytes": max_plain_text_bytes}
    searchable = True
    message = "File search completed."

    if mime_type.startswith("image/"):
        searchable = False
        message = "Image files are not text-searchable in the file viewer. Use OCR from the full evidence search."
    elif is_sqlite_candidate(source_path, suffix):
        try:
            sqlite_resume_state = decode_source_search_resume_token(
                sqlite_resume_token,
                source_path=source_path,
                keywords=normalized,
            ) if sqlite_resume_token else None
            matches, sqlite_truncated, search_diagnostics = search_sqlite_file(
                source_path,
                normalized,
                limit=limit,
                context=context,
                row_scan_limit=sqlite_row_scan_limit,
                resume_state=sqlite_resume_state,
            )
            if search_diagnostics.get("sqlite_resume_state"):
                token = encode_source_search_resume_token(
                    source_path=source_path,
                    keywords=normalized,
                    state=search_diagnostics["sqlite_resume_state"],
                )
                search_diagnostics["sqlite_resume_token"] = token
                search_diagnostics["sqlite_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            truncated = sqlite_truncated or len(matches) >= limit
            message = "SQLite text search completed."
        except sqlite3.DatabaseError as exc:
            searchable = False
            message = f"SQLite search failed: {exc}"
    elif suffix in SUPPORTED_DOC_EXTS:
        try:
            kind = suffix.lstrip(".")
            if file_resume_token or (stat.st_size > max_plain_text_bytes and kind in TEXT_EXTS):
                file_resume_state = decode_source_search_file_resume_token(
                    file_resume_token,
                    source_path=source_path,
                    keywords=normalized,
                ) if file_resume_token else None
                matches, truncated, search_diagnostics = search_large_byte_window_file(
                    source_path,
                    normalized,
                    limit=limit,
                    context=context,
                    max_scan_bytes=max_plain_text_bytes,
                    resume_state=file_resume_state,
                )
                if search_diagnostics.get("file_resume_state"):
                    token = encode_source_search_file_resume_token(
                        source_path=source_path,
                        keywords=normalized,
                        state=search_diagnostics["file_resume_state"],
                    )
                    search_diagnostics["file_resume_token"] = token
                    search_diagnostics["file_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
                message = "Large text file byte-window search completed."
            else:
                text = extract_text(
                    source_path,
                    kind,
                    max_input_bytes=max_plain_text_bytes,
                    max_archive_member_bytes=max_plain_text_bytes,
                    max_archive_total_bytes=max_plain_text_bytes,
                    max_pdf_stream_decompressed_bytes=max_plain_text_bytes,
                )
                matches = search_text_content(text, normalized, limit=limit, context=context)
        except HTTPException:
            raise
        except Exception as exc:
            searchable = False
            message = f"Text extraction failed: {exc}"
    elif stat.st_size <= max_plain_text_bytes and is_probably_binary(source_path):
        try:
            matches, truncated = search_binary_file(source_path, normalized, limit=limit, context=context)
            message = "Binary/hex byte search completed."
        except OSError as exc:
            searchable = False
            message = f"Binary search failed: {exc}"
    elif stat.st_size <= max_plain_text_bytes:
        try:
            matches, truncated = search_plain_text_file(source_path, normalized, limit=limit, context=context)
        except UnicodeError as exc:
            searchable = False
            message = f"Text decoding failed: {exc}"
    else:
        try:
            file_resume_state = decode_source_search_file_resume_token(
                file_resume_token,
                source_path=source_path,
                keywords=normalized,
            ) if file_resume_token else None
            matches, truncated, search_diagnostics = search_large_byte_window_file(
                source_path,
                normalized,
                limit=limit,
                context=context,
                max_scan_bytes=max_plain_text_bytes,
                resume_state=file_resume_state,
            )
            if search_diagnostics.get("file_resume_state"):
                token = encode_source_search_file_resume_token(
                    source_path=source_path,
                    keywords=normalized,
                    state=search_diagnostics["file_resume_state"],
                )
                search_diagnostics["file_resume_token"] = token
                search_diagnostics["file_resume_token_hash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            message = "Large file byte-window search completed."
        except OSError as exc:
            searchable = False
            message = f"Large file search failed: {exc}"

    search_diagnostics.setdefault("max_plain_text_bytes", max_plain_text_bytes)
    return {
        "command": "source-search",
        "path": str(source_path),
        "name": source_path.name,
        "extension": suffix,
        "size": stat.st_size,
        "mime_type": mime_type,
        "keywords": normalized,
        "searchable": searchable,
        "truncated": truncated or len(matches) >= limit,
        "message": message,
        "summary": {
            "match_count": len(matches),
            "limit": limit,
            **search_diagnostics,
        },
        "source_search_profile": source_search_profile(
            source_path=source_path,
            searchable=searchable,
            truncated=truncated or len(matches) >= limit,
            match_count=len(matches),
            limit=limit,
            context=context,
            diagnostics=search_diagnostics,
        ),
        "source_search_full_cursor_contract": build_source_search_full_cursor_contract(),
        "matches": enrich_source_search_matches(source_path, matches),
    }


def build_archived_source_search(
    archive_path: Path,
    entry_name: str,
    keywords: Sequence[str],
    *,
    limit: int = 100,
    context: int = 120,
    sqlite_resume_token: str | None = None,
    file_resume_token: str | None = None,
) -> dict[str, object]:
    if sqlite_resume_token or file_resume_token:
        raise HTTPException(status_code=400, detail="resume tokens are not supported for ZIP entry source-search")
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one keyword is required")
    try:
        preview, archive_entry = build_archived_source_read_preview(
            archive_path,
            entry_name=entry_name,
            max_chars=MAX_SOURCE_SEARCH_ARCHIVE_TEXT_CHARS,
            hex_bytes=HEX_PREVIEW_MAX_BYTES,
        )
    except SourceReadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    displayed_entry = str(archive_entry["archive_entry_name"])
    display_path = f"{archive_path}::{displayed_entry}"
    entry_path = Path(displayed_entry)
    suffix = entry_path.suffix.lower()
    mime_type = mimetypes.guess_type(entry_path.name)[0] or "application/octet-stream"
    searchable = preview.get("preview_type") == "text"
    matches: list[dict[str, object]] = []
    if searchable:
        matches = search_text_content(str(preview.get("text") or ""), normalized, limit=limit, context=context)
        for match in matches:
            match["archive_entry_name"] = displayed_entry
            match["archive_entry_crc32"] = archive_entry.get("archive_entry_crc32", "")
            match["source_viewer_locator"] = {
                "profile_version": "zip-entry-source-viewer-locator-v1",
                "locator_type": "zip-entry-text-preview",
                "container_path": str(archive_path),
                "archive_entry_name": displayed_entry,
                "archive_entry_index": archive_entry.get("archive_entry_index"),
                "archive_entry_crc32": archive_entry.get("archive_entry_crc32"),
                "line": match.get("line"),
                "offset": match.get("offset"),
                "keyword": match.get("keyword"),
            }
    truncated = bool(preview.get("truncated")) or len(matches) >= limit
    diagnostics = {
        "max_plain_text_bytes": MAX_SOURCE_SEARCH_ARCHIVE_TEXT_CHARS,
        "file_search_mode": "bounded-zip-entry-text" if searchable else "zip-entry-not-text-searchable",
        "archive_entry_name": displayed_entry,
        "archive_entry_crc32": archive_entry.get("archive_entry_crc32", ""),
        "archive_entry_size": archive_entry.get("archive_entry_size", 0),
        "container_path": str(archive_path),
        "container_type": "zip",
        "zip_entry_search": True,
    }
    enriched = enrich_source_search_matches(archive_path, matches)
    for item in enriched:
        item["source_path"] = display_path
        item["source_name"] = entry_path.name
        item["container_path"] = str(archive_path)
        item["archive_entry"] = archive_entry
        item["citation"] = (
            f"{archive_path.name}::{displayed_entry} line {item.get('line')} "
            f"offset {item.get('offset')} keyword {item.get('keyword')}"
        )
        if isinstance(item.get("citation_profile"), MutableMapping):
            item["citation_profile"]["source_path"] = display_path
            item["citation_profile"]["source_name"] = entry_path.name
            item["citation_profile"]["container_path"] = str(archive_path)
    return {
        "command": "source-search",
        "path": display_path,
        "container_path": str(archive_path),
        "archive_entry": archive_entry,
        "name": entry_path.name,
        "extension": suffix,
        "size": int(archive_entry["archive_entry_size"]),
        "container_size": archive_path.stat().st_size,
        "mime_type": mime_type,
        "keywords": normalized,
        "searchable": searchable,
        "truncated": truncated,
        "message": "ZIP entry text search completed." if searchable else "ZIP entry is not text-searchable in the bounded viewer.",
        "summary": {
            "match_count": len(matches),
            "limit": limit,
            **diagnostics,
        },
        "source_search_profile": source_search_profile(
            source_path=archive_path,
            searchable=searchable,
            truncated=truncated,
            match_count=len(matches),
            limit=limit,
            context=context,
            diagnostics=diagnostics,
        ),
        "source_search_full_cursor_contract": build_source_search_full_cursor_contract(),
        "matches": enriched,
    }


def source_search_profile(
    *,
    source_path: Path,
    searchable: bool,
    truncated: bool,
    match_count: int,
    limit: int,
    context: int,
    diagnostics: Mapping[str, object] | None = None,
) -> dict[str, object]:
    diagnostics = diagnostics or {}
    return {
        "profile_version": "current-file-search-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 17,
        "qc_prep_item_number": 56,
        "qc_prep_profile": "source-search-full-cursor-scan-v1",
        "source_search_full_cursor_contract": build_source_search_full_cursor_contract(),
        "source_path": str(source_path),
        "searchable": searchable,
        "match_count": match_count,
        "bounded_context_chars": context,
        "large_data_controls": {
            "result_limit": limit,
            "truncated": truncated,
            "document_extraction_limits": {
                "max_plain_text_bytes": max_plain_text_bytes_for_profile(diagnostics),
                "max_archive_member_bytes": max_plain_text_bytes_for_profile(diagnostics),
                "max_archive_total_bytes": max_plain_text_bytes_for_profile(diagnostics),
                "max_pdf_stream_decompressed_bytes": max_plain_text_bytes_for_profile(diagnostics),
                "limits_visible_to_gui": True,
            },
            "sqlite_row_scan_limit": diagnostics.get("sqlite_row_scan_limit"),
            "sqlite_scanned_row_count": diagnostics.get("sqlite_scanned_row_count"),
            "sqlite_scan_truncated": diagnostics.get("sqlite_scan_truncated"),
            "sqlite_full_cursor_scan": diagnostics.get("sqlite_full_cursor_scan"),
            "sqlite_result_limit_reached": diagnostics.get("sqlite_result_limit_reached"),
            "sqlite_resume_state": diagnostics.get("sqlite_resume_state"),
            "sqlite_resume_requested": diagnostics.get("sqlite_resume_requested"),
            "sqlite_resume_token": diagnostics.get("sqlite_resume_token"),
            "sqlite_resume_token_hash": diagnostics.get("sqlite_resume_token_hash"),
            "file_search_mode": diagnostics.get("file_search_mode"),
            "file_scan_start_offset": diagnostics.get("file_scan_start_offset"),
            "file_scan_end_offset": diagnostics.get("file_scan_end_offset"),
            "file_scanned_bytes": diagnostics.get("file_scanned_bytes"),
            "file_scan_truncated": diagnostics.get("file_scan_truncated"),
            "file_result_limit_reached": diagnostics.get("file_result_limit_reached"),
            "file_resume_state": diagnostics.get("file_resume_state"),
            "file_resume_requested": diagnostics.get("file_resume_requested"),
            "file_resume_token": diagnostics.get("file_resume_token"),
            "file_resume_token_hash": diagnostics.get("file_resume_token_hash"),
            "full_case_reindex_not_required": True,
            "sqlite_table_search_uses_limit": bool(diagnostics.get("sqlite_row_scan_limit")),
            "binary_search_is_bounded": True,
        },
        "reportability_decision": {
            "decision": "do-not-report-current-file-search-hit-without-viewer-citation",
            "allowed_use": "current-file-verification-pivot",
            "required_before_report": [
                "preserve line/offset/table locator",
                "copy citation into review note",
                "verify source hash if item is selected for report",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "large-file-search-benchmark-required",
            "source-search-trusted-locator-diff-required",
        ],
    }


def max_plain_text_bytes_for_profile(diagnostics: Mapping[str, object]) -> int:
    value = diagnostics.get("max_plain_text_bytes")
    return optional_int_for_api(value) or 50_000_000


def enrich_source_search_matches(source_path: Path, matches: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    enriched: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        locator = source_search_locator(match)
        citation = source_search_citation(source_path, match, locator)
        match_id = hashlib.sha256(f"{source_path}|{index}|{citation}|{match.get('snippet', '')}".encode()).hexdigest()[:16]
        citation_profile = source_search_citation_profile(source_path, match, locator, citation)
        item = dict(match)
        item.update(
            {
                "match_id": match_id,
                "match_index": index,
                "pointer": f"source-search:/matches/{index}",
                "source_path": str(source_path),
                "source_name": source_path.name,
                "locator": locator,
                "citation": citation,
                "citation_profile": citation_profile,
                "source_viewer_locator": citation_profile.get("source_viewer_locator", {}),
                "review_note_citation": citation_profile.get("review_note_citation", {}),
                "review_hint": "Use this citation in the viewer review note, then verify source hashes before reporting.",
                "compare_preview": f"{citation}\n{match.get('snippet', '')}",
            }
        )
        enriched.append(item)
    return enriched


def source_search_citation_profile(
    source_path: Path,
    match: Mapping[str, object],
    locator: Mapping[str, object],
    citation: str,
) -> dict[str, object]:
    locator_type = "sqlite-table-row" if locator.get("table") else "byte-offset" if locator.get("offset_hex") else "text-line-offset"
    source_viewer_locator = (
        locator.get("source_viewer_locator")
        if isinstance(locator.get("source_viewer_locator"), Mapping)
        else {}
    )
    review_note = (
        match.get("review_note_citation")
        if isinstance(match.get("review_note_citation"), Mapping)
        else sqlite_row_review_note_citation(source_viewer_locator)
        if source_viewer_locator
        else {}
    )
    return {
        "profile_version": "current-file-search-citation-v1",
        "item_number": 17,
        "qc_prep_item": 11 if locator_type == "sqlite-table-row" else 17,
        "source_path": str(source_path),
        "source_name": source_path.name,
        "locator_type": locator_type,
        "citation": citation,
        "keyword": str(match.get("keyword") or ""),
        "line": locator.get("line"),
        "offset": locator.get("offset"),
        "offset_hex": locator.get("offset_hex", ""),
        "table": locator.get("table", ""),
        "column": locator.get("column", ""),
        "row_number": locator.get("row_number", ""),
        "rowid": locator.get("rowid", ""),
        "primary_key_values": locator.get("primary_key_values", {}),
        "source_viewer_locator": dict(source_viewer_locator),
        "review_note_citation": dict(review_note),
        "report_draft_profile": source_search_report_draft_profile(
            source_path=source_path,
            match=match,
            locator=locator,
            citation=citation,
            review_note=review_note if isinstance(review_note, Mapping) else {},
        ),
        "ready_for_review_note": bool(citation and match.get("snippet")),
        "ready_for_report": False,
        "required_before_report": [
            "verify source file hash",
            "confirm locator in source viewer",
            "attach analyst review status",
        ],
        "commercial_grade_blockers": [
            "source-search-trusted-locator-diff-required",
            "source-hash-verification-required-for-report",
        ],
    }


def source_search_report_draft_profile(
    *,
    source_path: Path,
    match: Mapping[str, object],
    locator: Mapping[str, object],
    citation: str,
    review_note: Mapping[str, object],
) -> dict[str, object]:
    locator_payload = (
        locator.get("source_viewer_locator")
        if isinstance(locator.get("source_viewer_locator"), Mapping)
        else {}
    )
    return {
        "profile_version": "current-file-search-report-draft-profile-v1",
        "qc_prep_item": 14,
        "source_name": source_path.name,
        "citation": citation,
        "structured_citation": str(review_note.get("text") or ""),
        "source_locator_hash": str(locator_payload.get("locator_sha256") or ""),
        "snippet_sha256": hashlib.sha256(str(match.get("snippet") or "").encode("utf-8", errors="replace")).hexdigest()
        if match.get("snippet")
        else "",
        "ready_for_review_note": bool(citation and match.get("snippet")),
        "ready_for_report_draft": bool(citation and match.get("snippet")),
        "report_note_prefixes": ["Current-file hit:", "Structured citation:", "Source locator:", "Snippet:", "Review hint:"],
        "required_before_report": [
            "save source-search hit to review note",
            "verify source hash",
            "confirm locator in source viewer",
            "mark include_in_report intentionally",
        ],
    }


def encode_source_search_resume_token(*, source_path: Path, keywords: Sequence[str], state: Mapping[str, object]) -> str:
    safe_state = {
        key: state[key]
        for key in ("table", "next_row_number", "reason", "scanned_row_count", "match_count", "rowid")
        if key in state
    }
    payload = {
        "profile_version": "source-search-sqlite-resume-v1",
        "source_path_sha256": source_search_source_digest(source_path),
        "keywords_sha256": source_search_keywords_digest(keywords),
        "state": safe_state,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_source_search_resume_token(
    token: str,
    *,
    source_path: Path,
    keywords: Sequence[str],
) -> dict[str, object]:
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid sqlite_resume_token") from exc
    if not isinstance(payload, Mapping) or payload.get("profile_version") != "source-search-sqlite-resume-v1":
        raise HTTPException(status_code=400, detail="invalid sqlite_resume_token profile")
    if payload.get("source_path_sha256") != source_search_source_digest(source_path):
        raise HTTPException(status_code=400, detail="sqlite_resume_token does not match source file")
    if payload.get("keywords_sha256") != source_search_keywords_digest(keywords):
        raise HTTPException(status_code=400, detail="sqlite_resume_token does not match keywords")
    state = payload.get("state")
    if not isinstance(state, Mapping) or not state.get("table") or "next_row_number" not in state:
        raise HTTPException(status_code=400, detail="sqlite_resume_token is missing resume state")
    return {
        "table": str(state.get("table") or ""),
        "next_row_number": max(1, optional_int_for_api(state.get("next_row_number")) or 1),
        "reason": str(state.get("reason") or "resume-token"),
        "scanned_row_count": optional_int_for_api(state.get("scanned_row_count")) or 0,
        "match_count": optional_int_for_api(state.get("match_count")) or 0,
        "rowid": state.get("rowid", ""),
    }


def encode_source_search_file_resume_token(*, source_path: Path, keywords: Sequence[str], state: Mapping[str, object]) -> str:
    safe_state = {
        key: state[key]
        for key in ("next_offset", "reason", "scanned_bytes", "match_count", "last_match_offset")
        if key in state
    }
    payload = {
        "profile_version": "source-search-file-resume-v1",
        "source_path_sha256": source_search_source_digest(source_path),
        "keywords_sha256": source_search_keywords_digest(keywords),
        "state": safe_state,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_source_search_file_resume_token(
    token: str,
    *,
    source_path: Path,
    keywords: Sequence[str],
) -> dict[str, object]:
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid file_resume_token") from exc
    if not isinstance(payload, Mapping) or payload.get("profile_version") != "source-search-file-resume-v1":
        raise HTTPException(status_code=400, detail="invalid file_resume_token profile")
    if payload.get("source_path_sha256") != source_search_source_digest(source_path):
        raise HTTPException(status_code=400, detail="file_resume_token does not match source file")
    if payload.get("keywords_sha256") != source_search_keywords_digest(keywords):
        raise HTTPException(status_code=400, detail="file_resume_token does not match keywords")
    state = payload.get("state")
    if not isinstance(state, Mapping) or "next_offset" not in state:
        raise HTTPException(status_code=400, detail="file_resume_token is missing resume state")
    return {
        "next_offset": max(0, optional_int_for_api(state.get("next_offset")) or 0),
        "reason": str(state.get("reason") or "resume-token"),
        "scanned_bytes": optional_int_for_api(state.get("scanned_bytes")) or 0,
        "match_count": optional_int_for_api(state.get("match_count")) or 0,
        "last_match_offset": optional_int_for_api(state.get("last_match_offset")),
    }


def search_text_content(text: str, keywords: Sequence[str], *, limit: int, context: int) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    lowered = text.lower()
    for keyword in keywords:
        start = 0
        while len(matches) < limit:
            index = lowered.find(keyword, start)
            if index < 0:
                break
            line_number = text.count("\n", 0, index) + 1
            matches.append(
                {
                    "keyword": keyword,
                    "line": line_number,
                    "offset": index,
                    "snippet": snippet_around(text, index, len(keyword), context=context),
                }
            )
            start = index + max(len(keyword), 1)
        if len(matches) >= limit:
            break
    matches.sort(key=lambda item: int(item["offset"]))
    return matches


def search_plain_text_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
) -> tuple[list[dict[str, object]], bool]:
    matches: list[dict[str, object]] = []
    truncated = False
    with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_number, line in enumerate(handle, start=1):
            lowered = line.lower()
            for keyword in keywords:
                for match in re.finditer(re.escape(keyword), lowered):
                    matches.append(
                        {
                            "keyword": keyword,
                            "line": line_number,
                            "offset": match.start(),
                            "snippet": snippet_around(line.rstrip("\n"), match.start(), len(keyword), context=context),
                        }
                    )
                    if len(matches) >= limit:
                        truncated = True
                        return matches, truncated
    return matches, truncated


def search_binary_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
) -> tuple[list[dict[str, object]], bool]:
    data = source_path.read_bytes()
    lowered = data.lower()
    matches: list[dict[str, object]] = []
    for keyword in keywords:
        needle = keyword.encode("utf-8", errors="ignore").lower()
        if not needle:
            continue
        start = 0
        while len(matches) < limit:
            index = lowered.find(needle, start)
            if index < 0:
                break
            snippet_start = max(0, index - context)
            snippet_end = min(len(data), index + len(needle) + context)
            snippet = data[snippet_start:snippet_end]
            matches.append(
                {
                    "keyword": keyword,
                    "line": f"byte:{index}",
                    "offset": index,
                    "offset_hex": f"0x{index:08x}",
                    "byte_length": len(needle),
                    "snippet": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in snippet),
                    "hex_snippet": " ".join(f"{byte:02x}" for byte in snippet[:256]),
                }
            )
            start = index + max(len(needle), 1)
    matches.sort(key=lambda item: int(item["offset"]))
    return matches[:limit], len(matches) >= limit


def search_large_byte_window_file(
    source_path: Path,
    keywords: Sequence[str],
    *,
    limit: int,
    context: int,
    max_scan_bytes: int,
    resume_state: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], bool, dict[str, object]]:
    stat = source_path.stat()
    file_size = stat.st_size
    start_offset = min(max(0, optional_int_for_api((resume_state or {}).get("next_offset")) or 0), file_size)
    needles = [(keyword, keyword.encode("utf-8", errors="ignore").lower()) for keyword in keywords if keyword]
    needles = [(keyword, needle) for keyword, needle in needles if needle]
    overlap = min(max((len(needle) for _, needle in needles), default=1) + context, 1_048_576)
    scan_bytes = max(1, int(max_scan_bytes))
    scan_end_offset = min(file_size, start_offset + scan_bytes)
    read_end_offset = min(file_size, scan_end_offset + overlap)
    read_length = max(0, read_end_offset - start_offset)
    matches: list[dict[str, object]] = []
    result_limit_reached = False
    last_match_offset: int | None = None
    if read_length:
        with source_path.open("rb") as handle:
            handle.seek(start_offset)
            data = handle.read(read_length)
        lowered = data.lower()
        local_start = 0
        while len(matches) < limit:
            found: tuple[int, str, bytes] | None = None
            for keyword, needle in needles:
                index = lowered.find(needle, local_start)
                if index >= 0 and (found is None or index < found[0]):
                    found = (index, keyword, needle)
            if found is None:
                break
            index, keyword, needle = found
            absolute_offset = start_offset + index
            if absolute_offset >= scan_end_offset:
                break
            snippet_start = max(0, index - context)
            snippet_end = min(len(data), index + len(needle) + context)
            snippet = data[snippet_start:snippet_end]
            matches.append(
                {
                    "keyword": keyword,
                    "line": f"byte:{absolute_offset}",
                    "offset": absolute_offset,
                    "offset_hex": f"0x{absolute_offset:08x}",
                    "byte_length": len(needle),
                    "snippet": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in snippet),
                    "hex_snippet": " ".join(f"{byte:02x}" for byte in snippet[:256]),
                }
            )
            last_match_offset = absolute_offset
            local_start = index + max(len(needle), 1)
        if len(matches) >= limit:
            result_limit_reached = True
    matches.sort(key=lambda item: int(item["offset"]))
    next_resume_state: dict[str, object] | None = None
    if result_limit_reached and last_match_offset is not None:
        next_resume_state = {
            "next_offset": min(file_size, last_match_offset + 1),
            "reason": "result-limit",
            "scanned_bytes": max(0, scan_end_offset - start_offset),
            "match_count": len(matches),
            "last_match_offset": last_match_offset,
        }
    elif scan_end_offset < file_size:
        next_resume_state = {
            "next_offset": scan_end_offset,
            "reason": "byte-scan-limit",
            "scanned_bytes": max(0, scan_end_offset - start_offset),
            "match_count": len(matches),
        }
    truncated = bool(next_resume_state)
    return matches[:limit], truncated, {
        "file_search_mode": "bounded-byte-window",
        "file_scan_start_offset": start_offset,
        "file_scan_end_offset": scan_end_offset,
        "file_scanned_bytes": max(0, scan_end_offset - start_offset),
        "file_read_ahead_bytes": max(0, read_end_offset - scan_end_offset),
        "file_size": file_size,
        "file_scan_truncated": truncated,
        "file_result_limit_reached": result_limit_reached,
        "file_resume_state": next_resume_state,
        "file_resume_requested": bool(resume_state),
    }
