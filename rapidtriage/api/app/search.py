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

from .models import (
    BookmarkCreateRequest,
)


def source_search_locator(match: dict[str, object]) -> dict[str, object]:
    locator: dict[str, object] = {
        "line": match.get("line"),
        "offset": match.get("offset"),
        "keyword": match.get("keyword"),
    }
    for key in ("table", "column", "row_number", "rowid", "primary_key_values"):
        if key in match:
            locator[key] = match[key]
    if isinstance(match.get("source_viewer_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["source_viewer_locator"])
    elif isinstance(match.get("sqlite_row_locator"), Mapping):
        locator["source_viewer_locator"] = dict(match["sqlite_row_locator"])
    for key in ("offset_hex", "byte_length"):
        if key in match:
            locator[key] = match[key]
    return locator


def source_search_citation(source_path: Path, match: dict[str, object], locator: dict[str, object]) -> str:
    if locator.get("table"):
        return (
            f"{source_path.name} table {locator.get('table')} row {locator.get('row_number')} "
            f"column {locator.get('column')} keyword {locator.get('keyword')}"
        )
    if locator.get("offset_hex"):
        return (
            f"{source_path.name} byte offset {locator.get('offset_hex')} "
            f"length {locator.get('byte_length')} keyword {locator.get('keyword')}"
        )
    return f"{source_path.name} line {locator.get('line')} offset {locator.get('offset')} keyword {locator.get('keyword')}"


def source_search_source_digest(source_path: Path) -> str:
    try:
        normalized = str(source_path.resolve())
    except OSError:
        normalized = str(source_path)
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def source_search_keywords_digest(keywords: Sequence[str]) -> str:
    normalized = sorted(str(item).strip().lower() for item in keywords if str(item).strip())
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False).encode("utf-8")).hexdigest()


def snippet_around(text: str, index: int, length: int, *, context: int) -> str:
    start = max(0, index - context)
    end = min(len(text), index + length + context)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{text[start:end].strip()}{suffix}"


def normalize_bookmark_source(source: str) -> str:
    normalized = source.strip()
    aliases = {
        "timeline": "timeline",
        "files": "files",
        "docs": "docs",
        "indicators": "indicators",
        "compare": "compare",
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized.startswith("artifacts:"):
        kind = normalized.split(":", 1)[1].strip()
        if kind:
            return f"artifacts_{kind}"
    if normalized.startswith("artifacts_"):
        return normalized
    raise HTTPException(status_code=400, detail=f"unsupported bookmark source: {source}")


def normalize_bookmark_tags(request: BookmarkCreateRequest) -> list[str]:
    raw_tags: list[str] = []
    if request.tag:
        raw_tags.append(request.tag)
    if request.tags:
        raw_tags.extend(request.tags)
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw_tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags
